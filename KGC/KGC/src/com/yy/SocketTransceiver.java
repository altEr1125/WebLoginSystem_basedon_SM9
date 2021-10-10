package com.yy;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

/**
 * Socket�շ��� ͨ��Socket�������ݣ���ʹ�����̼߳���Socket���յ�������
 */
public abstract class SocketTransceiver implements Runnable {

	protected Socket socket;
	protected InetAddress addr;
	protected DataInputStream in;
	protected DataOutputStream out;
	private boolean runFlag;

	/**
	 * ʵ����
	 * 
	 * @param socket
	 *            �Ѿ��������ӵ�socket
	 */
	public SocketTransceiver(Socket socket) {
		this.socket = socket;
		this.addr = socket.getInetAddress();
	}

	/**
	 * ��ȡ���ӵ���Socket��ַ
	 * 
	 * @return InetAddress����
	 */
	public InetAddress getInetAddress() {
		return addr;
	}

	/**
	 * ����Socket�շ�
	 * <p>
	 * �������ʧ�ܣ���Ͽ����Ӳ��ص�{@code onDisconnect()}
	 */
	public void start() {
		runFlag = true;
		new Thread(this).start();
	}

	/**
	 * �Ͽ�����(����)
	 * <p>
	 * ���ӶϿ��󣬻�ص�{@code onDisconnect()}
	 */
	public void stop() {
		runFlag = false;
		try {
			socket.shutdownInput();
			in.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * �����ַ���
	 * 
	 * @param s
	 *            �ַ���
	 * @return ���ͳɹ�����true
	 */
	public boolean send(String s) {
		if (out != null) {
			try {
				out.writeUTF(s);
				out.flush();
				return true;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return false;
	}
	public boolean send(byte[] s) {
		if (out != null) {
			try {
				out.write(s);
				out.flush();
				return true;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return false;
	}

	/**
	 * ����Socket���յ�����(���߳�������)
	 */
	@Override
	public void run() {
		try {
			in = new DataInputStream(this.socket.getInputStream());
			out = new DataOutputStream(this.socket.getOutputStream());
		} catch (IOException e) {
			e.printStackTrace();
			runFlag = false;
		}
		while (runFlag) {
			try {
				final String s = in.readUTF();
				this.onReceive(addr, s);
			} catch (IOException e) {
				// ���ӱ��Ͽ�(����)
				runFlag = false;
			}
		}
		// �Ͽ�����
		try {
			in.close();
			out.close();
			socket.close();
			in = null;
			out = null;
			socket = null;
		} catch (IOException e) {
			e.printStackTrace();
		}
		this.onDisconnect(addr);
	}

	/**
	 * ���յ�����
	 * <p>
	 * ע�⣺�˻ص��������߳���ִ�е�
	 * 
	 * @param addr
	 *            ���ӵ���Socket��ַ
	 * @param s
	 *            �յ����ַ���
	 */
	public abstract void onReceive(InetAddress addr, String s);

	/**
	 * ���ӶϿ�
	 * <p>
	 * ע�⣺�˻ص��������߳���ִ�е�
	 * 
	 * @param addr
	 *            ���ӵ���Socket��ַ
	 */
	public abstract void onDisconnect(InetAddress addr);
}
