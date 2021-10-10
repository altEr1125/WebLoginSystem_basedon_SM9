package com.service;

import java.net.InetAddress;
import java.net.Socket;

/**
 * TCP Socket瀹㈡埛绔�
 */
public abstract class TcpClient implements Runnable {

	private int port;
	private String hostIP;
	private boolean connect = false;
	private SocketTransceiver transceiver;

	public void connect(String hostIP, int port) {
		this.hostIP = hostIP;
		this.port = port;
		new Thread(this).start();
	}

	@Override
	public void run() {
		try {
			Socket socket = new Socket(hostIP, port);
			transceiver = new SocketTransceiver(socket) {

				@Override
				public void onReceive(InetAddress addr, String s) {
					TcpClient.this.onReceive(this, s);
				}

				@Override
				public void onDisconnect(InetAddress addr) {
					connect = false;
					TcpClient.this.onDisconnect(this);
				}
			};
			transceiver.start();
			connect = true;
			this.onConnect(transceiver);
		} catch (Exception e) {
			e.printStackTrace();
			this.onConnectFailed();
		}
	}


	public void disconnect() {
		if (transceiver != null) {
			transceiver.stop();
			transceiver = null;
		}
	}


	public boolean isConnected() {
		return connect;
	}


	public SocketTransceiver getTransceiver() {
		return isConnected() ? transceiver : null;
	}


	public abstract void onConnect(SocketTransceiver transceiver);


	public abstract void onConnectFailed();

	/**
	 * 鎺ユ敹鍒版暟鎹�
	 * <p>
	 * 娉ㄦ剰锛氭鍥炶皟鏄湪鏂扮嚎绋嬩腑鎵ц鐨�
	 * 
	 * @param transceiver
	 *            SocketTransceiver瀵硅薄
	 * @param s
	 *            瀛楃涓�
	 */
	public abstract void onReceive(SocketTransceiver transceiver, String s);

	/**
	 * 杩炴帴鏂紑
	 * <p>
	 * 娉ㄦ剰锛氭鍥炶皟鏄湪鏂扮嚎绋嬩腑鎵ц鐨�
	 * 
	 * @param transceiver
	 *            SocketTransceiver瀵硅薄
	 */
	public abstract void onDisconnect(SocketTransceiver transceiver);
}
