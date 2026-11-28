package controller

import (
	"context"
	"errors"
	"strings"
	"time"

	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	coordination "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"

	policy "github.com/zekihan/gatehouse/internal/policy/v1alpha1"
)

const (
	leaderLease      = "gatehouse-status"
	ackPrefix        = "gatehouse-ack-"
	ackLabel         = policy.Group + "/ack"
	digestAnnotation = policy.Group + "/digest"
)

func (c *Controller) runStatus(ctx context.Context) {
	go c.runAcks(ctx)
	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metav1.ObjectMeta{Name: leaderLease, Namespace: c.options.Namespace},
		Client:     c.coordination,
		LockConfig: resourcelock.ResourceLockConfig{Identity: c.options.PodUID},
	}
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: 15 * time.Second,
		RenewDeadline: 10 * time.Second,
		RetryPeriod:   2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: c.statusLoop,
			OnStoppedLeading: func() {},
		},
		Name: leaderLease,
	})
	if err != nil {
		c.logger.ErrorContext(ctx, "Could not initialize status leader election")
		return
	}
	for ctx.Err() == nil {
		elector.Run(ctx)
	}
}

func (c *Controller) runAcks(ctx context.Context) {
	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := c.Snapshot()
			if c.Ready() && current != nil && c.writeAck(ctx, current.Digest) != nil {
				c.logger.WarnContext(ctx, "Could not acknowledge Gatehouse snapshot")
			}
		}
	}
}

func (c *Controller) writeAck(ctx context.Context, digest string) error {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	id := ackPrefix + c.options.PodName
	lease, err := c.leases.Get(ctx, id, metav1.GetOptions{})
	newLease := kerror.IsNotFound(err)
	if newLease {
		lease = &coordination.Lease{
			Name: id, Namespace: c.options.Namespace,
		}
	} else if err != nil {
		return err
	}
	if !newLease && value(lease.Spec.HolderIdentity, "") != c.options.PodUID &&
		len(lease.OwnerReferences) != 0 && lease.OwnerReferences[0].Name != c.options.PodName {
		return errors.New("acknowledgement Lease belongs to a different Pod")
	}
	lease.Labels = map[string]string{ackLabel: "true"}
	lease.Annotations = map[string]string{digestAnnotation: digest}
	lease.OwnerReferences = []metav1.OwnerReference{
		{APIVersion: "v1", Kind: "Pod", Name: c.options.PodName, UID: ktypes.UID(c.options.PodUID)},
	}
	now := metav1.NewMicroTime(time.Now())
	uid := c.options.PodUID
	fresh := int32(ackFreshness / time.Second)
	lease.Spec = coordination.LeaseSpec{
		HolderIdentity:       &uid,
		RenewTime:            &now,
		LeaseDurationSeconds: &fresh,
	}
	if newLease {
		_, err = c.leases.Create(ctx, lease, metav1.CreateOptions{})
	} else {
		_, err = c.leases.Update(ctx, lease, metav1.UpdateOptions{})
	}
	return err
}

func (c *Controller) statusLoop(ctx context.Context) {
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if current := c.currentReport(); current != nil {
				caughtUp := current.snapshot != nil &&
					c.allReplicasProgrammed(ctx, current.snapshot.Digest)
				c.publishStatus(ctx, current, caughtUp)
			}
		}
	}
}

func (c *Controller) allReplicasProgrammed(ctx context.Context, digest string) bool {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	items, err := c.client.Resource(pods.gvr).Namespace(c.options.Namespace).
		List(ctx, metav1.ListOptions{LabelSelector: c.options.PodSelector})
	if err != nil {
		return false
	}
	leases, err := c.leases.List(ctx, metav1.ListOptions{LabelSelector: ackLabel + "=true"})
	if err != nil {
		return false
	}
	acks := make(map[string]coordination.Lease, len(leases.Items))
	for _, lease := range leases.Items {
		acks[strings.TrimPrefix(lease.Name, ackPrefix)] = lease
	}
	ready := 0
	now := time.Now()
	for _, obj := range items.Items {
		pod, ok := decode[corev1.Pod](&obj)
		if !ok {
			return false
		}
		condition := podReady(pod)
		if condition == nil {
			continue
		}
		ready++
		if !acknowledged(pod, condition, acks[pod.Name], digest, now) {
			return false
		}
	}
	return ready > 0
}

func podReady(pod *corev1.Pod) *corev1.PodCondition {
	if pod.DeletionTimestamp != nil {
		return nil
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return &condition
		}
	}
	return nil
}

func acknowledged(
	pod *corev1.Pod,
	ready *corev1.PodCondition,
	ack coordination.Lease,
	digest string,
	now time.Time,
) bool {
	if value(ack.Spec.HolderIdentity, "") != string(pod.UID) ||
		ack.Annotations[digestAnnotation] != digest ||
		ack.Spec.RenewTime == nil {
		return false
	}
	renewed := ack.Spec.RenewTime.Time
	return !renewed.Before(ready.LastTransitionTime.Time) &&
		now.Sub(renewed) < ackFreshness && renewed.Before(now.Add(ackInterval))
}
