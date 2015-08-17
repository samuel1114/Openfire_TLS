package com.sabaothtech;

import java.io.IOException;

import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.ConnectionListener;
import org.jivesoftware.smack.ReconnectionManager;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.StanzaListener;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.filter.StanzaFilter;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;


public class Example {
    private final String serverAddress = "server address";
    private final int serverPort = 5222;
    private final int connectTimeout = 15000;
    private final int sentPackageTimeout = 25000;

    private static XMPPTCPConnection connection = null;
    private static XMPPTCPConnectionConfiguration.Builder config = null;
    private String resource;
    private boolean isResumeConnection = true;

    private ConnectionListener XMPPConnListener = new ConnectionListener() {

        @Override
        public void connected(XMPPConnection xmppConnection) {
        	System.out.println("connected");
        }

        @Override
        public void authenticated(XMPPConnection xmppConnection, boolean b) {
        	System.out.println("authenticated");
        }

        @Override
        public void connectionClosed() {
        	System.out.println("connectionClosed");
            isResumeConnection = false;
            resumeConnection();
        }

        @Override
        public void connectionClosedOnError(Exception ex) {
        	System.out.println("connectionClosedOnError");
            isResumeConnection = true;
            resumeConnection();
        }

        @Override
        public void reconnectingIn(int arg0) {
        	System.out.println("reconnectingIn");
        }

        @Override
        public void reconnectionFailed(Exception ex) {
        	System.out.println("reconnectionFailed");
            isResumeConnection = true;
            resumeConnection();
        }

        @Override
        public void reconnectionSuccessful() {
        	System.out.println("reconnectionSuccessful");
        }
    };
    
	public static void main(String[] args) {
		(new Example()).connectServer();
		while (true) {
			
		}
	}
	
	private void resumeConnection() {
        if (isResumeConnection) {
            connectServer();
        }
    }

    private void setConfiguration() throws Exception {
        if (config == null) {
            config = XMPPTCPConnectionConfiguration.builder()
                    .setSecurityMode(ConnectionConfiguration.SecurityMode.disabled)
                    .setSocketFactory(HTTPSTrustManager.getSSLContextAllowAll().getSocketFactory())
                    //.setCustomSSLContext(HTTPSTrustManager.getSSLContextAllowAll())
                    .setServiceName(serverAddress)
                    .setSendPresence(true)
                    .setCompressionEnabled(false)
                    .setHost(serverAddress)
                    .setPort(serverPort)
                    .setResource(resource)
                    .setUsernameAndPassword("user_account", "password")
                    .setDebuggerEnabled(true)
                    .setConnectTimeout(connectTimeout);
        }
    }

    public void connectServer() {
    	resource = "example_resource";
        try {
			setConfiguration();
			setupConnection();
	        setupChat();
	        startConnectServer();
		} catch (Exception e) {
			e.printStackTrace();
		}
    }

    private void setupConnection() {
        if (connection == null) {
            connection = new XMPPTCPConnection(config.build());
            connection.setPacketReplyTimeout(sentPackageTimeout);
            connection.addConnectionListener(XMPPConnListener);
            startReconnectionManager();
        }
    }

    private void startReconnectionManager() {
        /*http://www.igniterealtime.org/builds/smack/docs/latest/javadoc/org/jivesoftware/smack/ReconnectionManager.html*/
        ReconnectionManager.getInstanceFor(connection).enableAutomaticReconnection();
    }

    private void stopReconnectionManager() {
        /*http://www.igniterealtime.org/builds/smack/docs/latest/javadoc/org/jivesoftware/smack/ReconnectionManager.html*/
        ReconnectionManager.getInstanceFor(connection).disableAutomaticReconnection();
    }
    
    private void setupChat() {
    	StanzaFilter myFilter = new StanzaFilter() {
            public boolean accept(Stanza packet) {
                if (packet != null) {
                    if (packet instanceof Message) {
                        return true;
                    }
                }
                return false;
            }
        };
        connection.addAsyncStanzaListener(
                new StanzaListener() {

                    @Override
                    public void processPacket(Stanza packet) throws SmackException.NotConnectedException {
                        if (packet != null) {
                            if (packet instanceof Message) {
                                Message message = ((Message) packet);
                                String from = message.getFrom();
                                String body = message.getBody();
                               
                                System.out.println(String.format("Received message '%1$s' from %2$s", body, from));
                            }
                        }
                    }
                },
                myFilter);
    }
    
    private void startConnectServer() {
        try {
            if (connection != null && !connection.isConnected()) {
                connection.connect();
            }
            if (connection != null && !connection.isAuthenticated()) {
                SASLAuthentication.unBlacklistSASLMechanism(SASLMechanism.PLAIN);
                SASLAuthentication.blacklistSASLMechanism(SASLMechanism.DIGESTMD5);
                SASLAuthentication.blacklistSASLMechanism(SASLMechanism.CRAMMD5);
                SASLAuthentication.blacklistSASLMechanism(SASLMechanism.EXTERNAL);
                SASLAuthentication.blacklistSASLMechanism(SASLMechanism.GSSAPI);
                connection.login();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SmackException e) {
            e.printStackTrace();
        } catch (XMPPException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
    }

    private void disconnectServer() {
        if (connection != null && connection.isConnected()) {
            stopReconnectionManager();
            connection.disconnect();
            connection = null;
            config = null;
        }
    }
}
