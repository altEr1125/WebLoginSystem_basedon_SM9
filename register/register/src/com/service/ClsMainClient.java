package com.service;

import java.io.File;
import java.io.IOException;
public class ClsMainClient {

	public static void conn(String ip,int port,String id,String msg) {
		TcpClient c1 = new TcpClient() {

			@Override
			public void onReceive(SocketTransceiver st, String s) {
				Parameter_tran p = new Parameter_tran();
				p.setEncrypt_str(s);
				System.out.println("Client1 Receive: " + s);
			}

			@Override
			public void onDisconnect(SocketTransceiver st) {
				System.out.println("Client1 Disconnect");
			}

			@Override
			public void onConnect(SocketTransceiver transceiver) {
				System.out.println("Client1 Connect");
			}

			@Override
			public void onConnectFailed() {
				System.out.println("Client1 Connect Failed");
			}
			
		};
//		TcpClient c2 = new TcpClient() {
//
//			@Override
//			public void onReceive(SocketTransceiver st, String s) {
//				System.out.println("Client2 Receive: " + s);
//			}
//
//			@Override
//			public void onDisconnect(SocketTransceiver st) {
//				System.out.println("Client2 Disconnect");
//			}
//
//			@Override
//			public void onConnect(SocketTransceiver transceiver) {
//				System.out.println("Client2 Connect");
//			}
//
//			@Override
//			public void onConnectFailed() {
//				System.out.println("Client2 Connect Failed");
//			}
//		};
		c1.connect(ip, port);
//		c2.connect("127.0.0.1", 12323);
		delay();
//		while (true) {
			if (c1.isConnected()) {
				String str = "falg:encrypt;id:" + id + ";msg:" + msg + ";";
				c1.getTransceiver().send(str);
			} else {
//				break;
			}
			delay();
//			if (c2.isConnected()) {
//				c2.getTransceiver().send("Hello2");
//			} else {
//				break;
//			}
//			delay();
		}
//	}
	static void delay() {
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
