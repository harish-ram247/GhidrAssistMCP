package ghidrassistmcp;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Non-blocking admission for MCP work and exclusive project lifecycle operations.
 * Permits can be released by a different thread after an asynchronous task really exits.
 */
public final class ProjectOperationGate {
    private final Map<Object, String> activeOperations = new LinkedHashMap<>();
    private boolean transitionActive;

    public Runnable acquireOperation() { return acquireOperation("MCP request"); }

    public synchronized Runnable acquireOperation(String name) {
        if (transitionActive) {
            throw new IllegalStateException("A Ghidra project operation is in progress. Retry after it completes.");
        }
        Object permit = new Object();
        activeOperations.put(permit, name);
        return () -> {
            synchronized (ProjectOperationGate.this) {
                activeOperations.remove(permit);
            }
        };
    }

    public synchronized Runnable acquireTransition() {
        if (transitionActive) {
            throw new IllegalStateException("A Ghidra project operation is already in progress. Retry after it completes.");
        }
        if (!activeOperations.isEmpty()) {
            throw new IllegalStateException("Cannot change or save the Ghidra project while "
                + activeOperations.size() + (activeOperations.size() == 1 ? " MCP operation is active (" : " MCP operations are active (")
                + String.join(", ", new TreeSet<>(activeOperations.values())) + "). Wait for them to finish, then retry.");
        }
        transitionActive = true;
        AtomicBoolean released = new AtomicBoolean();
        return () -> {
            if (released.compareAndSet(false, true)) {
                synchronized (ProjectOperationGate.this) {
                    transitionActive = false;
                }
            }
        };
    }
}
