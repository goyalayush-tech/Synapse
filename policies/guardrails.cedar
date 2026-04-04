// =============================================================================
// SYNAPSE GOVERNANCE POLICIES (Cedar)
// =============================================================================
// These policies implement the "Judge" plane of the Agentic Mesh architecture.
// They enforce Attribute-Based Access Control (ABAC) on all agent operations.
//
// Core Philosophy: "Deny by Default, Allow by Policy"
// =============================================================================

// -----------------------------------------------------------------------------
// NAMESPACE DEFINITIONS
// -----------------------------------------------------------------------------

// Agent principals - identified by SPIFFE ID or eBPF-attested process
// Example: Agent::"spiffe://synapse.local/agent/code-reviewer"

// Actions that agents can perform
// - "read": Query vector memory or CRDT state
// - "write": Append to event log or modify CRDT
// - "execute": Invoke tool or delegate to another agent
// - "admin": Manage policies or node configuration

// Resources within the Synapse mesh
// - Topic::"events.auth" - Event stream topics
// - State::"task.status" - CRDT state keys
// - Tool::"code_search" - MCP tools

// -----------------------------------------------------------------------------
// BASELINE POLICIES
// -----------------------------------------------------------------------------

// Policy: Allow authenticated agents to read their own namespaced data
permit(
    principal,
    action == Action::"read",
    resource
)
when {
    // Agent can read resources in their own namespace
    principal.namespace == resource.namespace
};

// Policy: Allow agents to write to event streams they own
permit(
    principal,
    action == Action::"write",
    resource
)
when {
    resource is Topic &&
    resource.owner == principal
};

// Policy: Allow agents to read shared collaboration state
permit(
    principal,
    action == Action::"read",
    resource
)
when {
    resource is State &&
    resource.shared == true
};

// Policy: Allow agents to modify shared state if they are collaborators
permit(
    principal,
    action == Action::"write",
    resource
)
when {
    resource is State &&
    resource.shared == true &&
    principal in resource.collaborators
};

// -----------------------------------------------------------------------------
// TOOL EXECUTION POLICIES
// -----------------------------------------------------------------------------

// Policy: Allow agents to execute tools they have capability for
permit(
    principal,
    action == Action::"execute",
    resource
)
when {
    resource is Tool &&
    resource.name in principal.capabilities
};

// Policy: Rate limit tool execution (checked via context)
forbid(
    principal,
    action == Action::"execute",
    resource
)
when {
    context.rate_limit_exceeded == true
};

// -----------------------------------------------------------------------------
// DELEGATION POLICIES (A2A)
// -----------------------------------------------------------------------------

// Policy: Allow agent-to-agent delegation within trust boundary
permit(
    principal,
    action == Action::"delegate",
    resource
)
when {
    resource is Agent &&
    principal.trust_domain == resource.trust_domain
};

// Policy: Forbid delegation to untrusted agents
forbid(
    principal,
    action == Action::"delegate",
    resource
)
when {
    resource is Agent &&
    resource.trust_level < 2
};

// -----------------------------------------------------------------------------
// ADMIN POLICIES
// -----------------------------------------------------------------------------

// Policy: Only admin agents can modify policies
permit(
    principal,
    action == Action::"admin",
    resource
)
when {
    principal.role == "admin" &&
    context.authenticated_via == "ebpf"
};

// Policy: Forbid admin actions from remote agents
forbid(
    principal,
    action == Action::"admin",
    resource
)
when {
    context.connection_type == "remote"
};

// -----------------------------------------------------------------------------
// SECURITY GUARDRAILS
// -----------------------------------------------------------------------------

// Policy: Forbid access to sensitive topics without explicit grant
forbid(
    principal,
    action,
    resource
)
when {
    resource is Topic &&
    resource.sensitivity == "high" &&
    !principal.has_clearance("high")
};

// Policy: Forbid writing to immutable resources
forbid(
    principal,
    action == Action::"write",
    resource
)
when {
    resource.immutable == true
};

// Policy: Audit all admin actions
// (This is a marker policy - actual auditing happens in the engine)
permit(
    principal,
    action == Action::"admin",
    resource
)
when {
    context.audit_logged == true
};
