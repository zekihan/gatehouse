These unmodified Apache-2.0 Lua health checks are from Argo CD v3.6.3,
commit `b4accc482028fd529b3e4508ef9f28977b552b50`, under
`resource_customizations/gateway.networking.k8s.io/<kind>/health.lua`.

Gateway, ListenerSet, HTTPRoute and TLSRoute report Progressing while
Gatehouse reports Programmed=False. The pinned BackendTLSPolicy check
evaluates Accepted and ResolvedRefs and ignores Programmed. Gatehouse
still emits Programmed on its BackendTLSPolicy ancestors.
