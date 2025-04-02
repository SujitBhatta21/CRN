// IN2011 Computer Networks
// Coursework 2024/2025
//
// Submission by
//  Name: Sujit Bhatta
//  Student ID: 230016132
//  E-mail: sujit.bhatta@city.ac.uk


// DO NOT EDIT starts
// This gives the interface that your code must implement.
// These descriptions are intended to help you understand how the interface
// will be used. See the RFC for how the protocol works.

import javax.xml.crypto.Data;
import java.io.IOException;
import java.net.*;
import java.security.MessageDigest;
import java.util.*;

interface NodeInterface {

    /* These methods configure your node.
     * They must both be called once after the node has been created but
     * before it is used. */

    // Set the name of the node.
    public void setNodeName(String nodeName) throws Exception;

    // Open a UDP port for sending and receiving messages.
    public void openPort(int portNumber) throws Exception;


    /*
     * These methods query and change how the network is used.
     */

    // Handle all incoming messages.
    // If you wait for more than delay miliseconds and
    // there are no new incoming messages return.
    // If delay is zero then wait for an unlimited amount of time.
    public void handleIncomingMessages(int delay) throws Exception;

    // Determines if a node can be contacted and is responding correctly.
    // Handles any messages that have arrived.
    public boolean isActive(String nodeName) throws Exception;

    // You need to keep a stack of nodes that are used to relay messages.
    // The base of the stack is the first node to be used as a relay.
    // The first node must relay to the second node and so on.

    // Adds a node name to a stack of nodes used to relay all future messages.
    public void pushRelay(String nodeName) throws Exception;

    // Pops the top entry from the stack of nodes used for relaying.
    // No effect if the stack is empty
    public void popRelay() throws Exception;


    /*
     * These methods provide access to the basic functionality of
     * CRN-25 network.
     */

    // Checks if there is an entry in the network with the given key.
    // Handles any messages that have arrived.
    public boolean exists(String key) throws Exception;

    // Reads the entry stored in the network for key.
    // If there is a value, return it.
    // If there isn't a value, return null.
    // Handles any messages that have arrived.
    public String read(String key) throws Exception;

    // Sets key to be value.
    // Returns true if it worked, false if it didn't.
    // Handles any messages that have arrived.
    public boolean write(String key, String value) throws Exception;

    // If key is set to currentValue change it to newValue.
    // Returns true if it worked, false if it didn't.
    // Handles any messages that have arrived.
    public boolean CAS(String key, String currentValue, String newValue) throws Exception;

}
// DO NOT EDIT ends


// Complete this!
public class Node implements NodeInterface {
    private String nodeName;
    private DatagramSocket socket;
    private final Map<String, String> store = new HashMap<>();
    private final Stack<String> relayStack = new Stack<>();
    private final Map<String, InetSocketAddress> addressBook = new HashMap<>();
    private final Map<String, String> nearestResponseCache = new HashMap<>();
    private final Random random = new Random();
    private String lastReadResult = null;
    private final boolean debug = false;

    @Override
    public void setNodeName(String nodeName) throws Exception {
        if (!nodeName.startsWith("N:")) throw new IllegalArgumentException("Node name must start with 'N:'");
        this.nodeName = nodeName;
    }

    @Override
    public void openPort(int portNumber) throws Exception {
        this.socket = new DatagramSocket(portNumber);
        if (debug) System.out.println("Listening on UDP port " + portNumber);
    }

    @Override
    public void handleIncomingMessages(int delay) throws Exception {
        socket.setSoTimeout(100);
        byte[] buffer = new byte[2048];
        long start = System.currentTimeMillis();
        while (delay == 0 || System.currentTimeMillis() - start < delay) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
                String msg = new String(packet.getData(), 0, packet.getLength());
                if (debug) System.out.println("Received: " + msg);
                processMessage(msg, packet.getAddress(), packet.getPort());
            } catch (SocketTimeoutException ignored) {}
        }
    }

    private void processMessage(String message, InetAddress address, int port) {
        try {
            String[] parts = message.trim().split(" ", 3);
            if (parts.length < 2) return;
            String txID = parts[0], type = parts[1];

            switch (type) {
                case "G" -> sendResponse(address, port, txID + " H " + encode(nodeName));
                case "H" -> addressBook.put(decode(parts[2]), new InetSocketAddress(address, port));
                case "W" -> {
                    String[] kv = decodeTwo(parts[2]);
                    if (kv != null) {
                        store.put(kv[0], kv[1]);
                        if (kv[0].startsWith("N:")) {
                            String[] ipPort = kv[1].split(":");
                            if (ipPort.length == 2)
                                addressBook.put(kv[0], new InetSocketAddress(ipPort[0], Integer.parseInt(ipPort[1])));
                        }
                        sendResponse(address, port, txID + " X A");
                    }
                }
                case "R" -> {
                    String key = decode(parts[2]);
                    if (store.containsKey(key))
                        sendResponse(address, port, txID + " S Y " + encode(store.get(key)));
                    else
                        sendResponse(address, port, txID + " S N ");
                }
                case "S" -> {
                    String[] resp = parts[2].split(" ", 2);
                    if (resp.length > 1 && resp[0].equals("Y"))
                        lastReadResult = decode(resp[1]);
                }
                case "N" -> {
                    String hash = parts[2].trim();
                    List<String> keys = new ArrayList<>(addressBook.keySet());
                    keys.removeIf(k -> !k.startsWith("N:"));
                    keys.sort(Comparator.comparingInt(k -> {
                        try { return distance(hash, sha256Hex(k)); }
                        catch (Exception e) { return Integer.MAX_VALUE; }
                    }));
                    StringBuilder oReply = new StringBuilder(txID + " O");
                    for (int i = 0; i < Math.min(3, keys.size()); i++) {
                        String k = keys.get(i);
                        String v = addressBook.get(k).getAddress().getHostAddress() + ":" + addressBook.get(k).getPort();
                        oReply.append(" ").append(encode(k)).append(encode(v));
                    }
                    sendResponse(address, port, oReply.toString());
                }
                case "O" -> nearestResponseCache.put(txID, parts[2]);
                case "I" -> {} // Ignore welcome message
            }
        } catch (Exception e) {
            if (debug) System.err.println("Error processing: " + e.getMessage());
        }
    }

    private void sendResponse(InetAddress address, int port, String message) {
        try {
            byte[] data = message.getBytes();
            DatagramPacket packet = new DatagramPacket(data, data.length, address, port);
            socket.send(packet);
            if (debug) System.out.println("Sent: " + message);
        } catch (IOException e) {
            if (debug) System.err.println("Send error: " + e.getMessage());
        }
    }

    private String encode(String s) {
        long spaces = s.chars().filter(c -> c == ' ').count();
        return spaces + " " + s + " ";
    }

    private String decode(String s) {
        int space = s.indexOf(' ');
        return (space != -1) ? s.substring(space + 1, s.length() - 1) : null;
    }

    private String[] decodeTwo(String s) {
        try {
            String[] parts = s.trim().split(" ", 4);
            return new String[]{parts[1], parts[3]};
        } catch (Exception e) { return null; }
    }

    @Override public boolean isActive(String nodeName) { return addressBook.containsKey(nodeName); }
    @Override public void pushRelay(String nodeName) { relayStack.push(nodeName); }
    @Override public void popRelay() { if (!relayStack.isEmpty()) relayStack.pop(); }
    @Override public boolean exists(String key) { return store.containsKey(key); }

    @Override
    public String read(String key) throws Exception {
        if (store.containsKey(key)) return store.get(key);

        String targetHash = sha256Hex(key);
        Set<String> tried = new HashSet<>();
        Queue<String> toTry = new LinkedList<>();

        if (addressBook.isEmpty())
            addressBook.put("N:azure", new InetSocketAddress("10.200.51.19", 20114));

        toTry.addAll(addressBook.keySet());

        while (!toTry.isEmpty()) {
            String node = toTry.poll();
            if (tried.contains(node) || !addressBook.containsKey(node)) continue;
            tried.add(node);

            InetSocketAddress addr = addressBook.get(node);
            String txID = genTxID();
            lastReadResult = null;
            sendResponse(addr.getAddress(), addr.getPort(), txID + " R " + encode(key));

            long start = System.currentTimeMillis();
            while (System.currentTimeMillis() - start < 1000) {
                handleIncomingMessages(100);
                if (lastReadResult != null) return cleanPoem(lastReadResult);
            }

            String nearestTx = genTxID();
            sendResponse(addr.getAddress(), addr.getPort(), nearestTx + " N " + targetHash);

            long t2 = System.currentTimeMillis();
            while (!nearestResponseCache.containsKey(nearestTx) && System.currentTimeMillis() - t2 < 1000) {
                handleIncomingMessages(100);
            }

            String oData = nearestResponseCache.get(nearestTx);
            if (oData == null) continue;

            String[] parts = oData.trim().split(" ");
            for (int i = 0; i + 3 < parts.length; i += 4) {
                String peerKey = parts[i + 1];
                String peerVal = parts[i + 3];
                if (peerKey.startsWith("N:") && peerVal.contains(":")) {
                    String[] ipPort = peerVal.split(":");
                    InetSocketAddress peerAddr = new InetSocketAddress(ipPort[0], Integer.parseInt(ipPort[1]));
                    addressBook.put(peerKey, peerAddr);
                    if (!tried.contains(peerKey)) toTry.add(peerKey);
                }
            }
        }

        return null;
    }

    private String cleanPoem(String raw) {
        return raw.strip().replaceAll("[\\r\\n]+", "\n");
    }

    @Override
    public boolean write(String key, String value) throws Exception {
        store.put(key, value);
        for (InetSocketAddress addr : addressBook.values()) {
            String txID = genTxID();
            sendResponse(addr.getAddress(), addr.getPort(), txID + " W " + encode(key) + encode(value));
        }
        return true;
    }

    @Override
    public boolean CAS(String key, String currentValue, String newValue) {
        if (!store.containsKey(key)) {
            store.put(key, newValue); return true;
        } else if (store.get(key).equals(currentValue)) {
            store.put(key, newValue); return true;
        }
        return false;
    }

    private String genTxID() {
        char a = (char) ('A' + random.nextInt(26));
        char b = (char) ('A' + random.nextInt(26));
        return "" + a + b;
    }

    private String sha256Hex(String s) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(s.getBytes("UTF-8"));
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) hex.append(String.format("%02x", b));
        return hex.toString();
    }

    private int distance(String h1, String h2) {
        for (int i = 0; i < h1.length(); i++) {
            int n1 = Integer.parseInt(h1.substring(i, i + 1), 16);
            int n2 = Integer.parseInt(h2.substring(i, i + 1), 16);
            int xor = n1 ^ n2;
            for (int bit = 3; bit >= 0; bit--) {
                if (((xor >> bit) & 1) == 1) {
                    return i * 4 + (3 - bit);
                }
            }
        }
        return 256;
    }
}