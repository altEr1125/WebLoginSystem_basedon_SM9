package com.yy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * TCP Socket��������
 */
public abstract class TcpServer implements Runnable {

	private int port;
	private boolean runFlag;
	private List<SocketTransceiver> clients = new ArrayList<SocketTransceiver>();

	/**
	 * ʵ����
	 * 
	 * @param port
	 *            �����Ķ˿�
	 */
	public TcpServer(int port) {
		this.port = port;
	}

	/**
	 * ����������
	 * <p>
	 * �������ʧ�ܣ���ص�{@code onServerStop()}
	 */
	public void start() {
		runFlag = true;
		new Thread(this).start();
	}

	/**
	 * ֹͣ������
	 * <p>
	 * ������ֹͣ�󣬻�ص�{@code onServerStop()}
	 */
	public void stop() {
		runFlag = false;
	}

	/**
	 * �����˿ڣ����ܿͻ�������(���߳�������)
	 */
	@Override
	public void run() {
		try {
			final ServerSocket server = new ServerSocket(port);
			while (runFlag) {
				try {
					final Socket socket = server.accept();
					startClient(socket);
				} catch (IOException e) {
					// ���ܿͻ������ӳ���
					e.printStackTrace();
					this.onConnectFailed();
				}
			}
			// ֹͣ���������Ͽ���ÿ���ͻ��˵�����
			try {
				for (SocketTransceiver client : clients) {
					client.stop();
				}
				clients.clear();
				server.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		} catch (IOException e) {
			// ServerSocket���󴴽���������������ʧ��
			e.printStackTrace();
		}
		this.onServerStop();
	}

	/**
	 * �����ͻ����շ�
	 * 
	 * @param socket
	 */
	private void startClient(final Socket socket) {
		SocketTransceiver client = new SocketTransceiver(socket) {

			@Override
			public void onReceive(InetAddress addr, String s) {
				TcpServer.this.onReceive(this, s);
			}

			@Override
			public void onDisconnect(InetAddress addr) {
				clients.remove(this);
				TcpServer.this.onDisconnect(this);
			}
		};
		client.start();
		clients.add(client);
		this.onConnect(client);
	}

	/**
	 * �ͻ��ˣ����ӽ���
	 * <p>
	 * ע�⣺�˻ص��������߳���ִ�е�
	 * 
	 * @param client
	 *            SocketTransceiver����
	 */
	public abstract void onConnect(SocketTransceiver client);

	/**
	 * �ͻ��ˣ����ӽ���ʧ��
	 * <p>
	 * ע�⣺�˻ص��������߳���ִ�е�
	 */
	public abstract void onConnectFailed();

	/**
	 * �ͻ��ˣ��յ��ַ���
	 * <p>
	 * ע�⣺�˻ص��������߳���ִ�е�
	 * 
	 * @param client
	 *            SocketTransceiver����
	 * @param s
	 *            �ַ���
	 */
	public abstract void onReceive(SocketTransceiver client, String s);

	/**
	 * �ͻ��ˣ����ӶϿ�
	 * <p>
	 * ע�⣺�˻ص��������߳���ִ�е�
	 * 
	 * @param client
	 *            SocketTransceiver����
	 */
	public abstract void onDisconnect(SocketTransceiver client);

	/**
	 * ������ֹͣ
	 * <p>
	 * ע�⣺�˻ص��������߳���ִ�е�
	 */
	public abstract void onServerStop();
}
