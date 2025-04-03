import java.net.InetSocketAddress;

// Pseudocode: Tracking outgoing requests
public class PendingRequest {
    String txID;
    InetSocketAddress target;
    long timestamp;
    int retries;
    String message;  // The full request message to be resent

    public PendingRequest(String txID, InetSocketAddress target, String message) {
        this.txID = txID;
        this.target = target;
        this.message = message;
        this.timestamp = System.currentTimeMillis();
        this.retries = 0;
    }
}
