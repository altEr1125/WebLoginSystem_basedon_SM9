package com.yy;

import com.kgcmaster.KGCMaster;
import com.yy.gm.sm3.SM3;
import com.yy.gm.sm9.MasterKeyPair;
import com.yy.gm.sm9.MasterPublicKey;
import com.yy.gm.sm9.PrivateKey;
import com.yy.gm.sm9.PrivateKeyType;
import com.yy.gm.sm9.ResultCipherText;
import com.yy.gm.sm9.SM9;
import com.yy.gm.sm9.SM9Curve;
import com.yy.test.SM9Test;
import com.yy.utils.Hex;

public class Main {
	public static void main(String[] args) {
		int port = 12332;
		SM9Curve sm9Curve = new SM9Curve();//生成曲线参数
		SM9 sm9 = new SM9(sm9Curve);
		KGCMaster kgcMaster = new KGCMaster();
		MasterKeyPair encryptMasterKeyPair = kgcMaster.getKgc().genEncryptMasterKeyPair();
		MasterPublicKey masterPublicKey = encryptMasterKeyPair.getPublicKey();



		TcpServer server = new TcpServer(port) {

			@Override
			public void onConnect(SocketTransceiver client) {
				printInfo(client, "Connect");
			}

			@Override
			public void onConnectFailed() {
				System.out.println("Client Connect Failed");
			}

			@Override
			public void onReceive(SocketTransceiver client, String s) {
				printInfo(client, "Receive Data: " + s);
				String[] strArray = new String[10];
				strArray = s.split(";");
				
				String[] flag = new String[2];
				try {
				flag = strArray[0].split(":");
				
				if(flag[1]!=null&&flag[1].equals("encrypt")) {

					String[] k_id = new String[2];
					k_id = strArray[1].split(":");
					String id_B = k_id[1];
					String[] k_msg = new String[2];
					k_msg = strArray[2].split(":");
					String msg = k_msg[1];

					byte[] resultCipherText;
					String[] hexData = new String[1];
					try {
						resultCipherText = SM9Test.encrypt(kgcMaster.getKgc(), sm9,masterPublicKey,id_B, msg);
						hexData[0] = Hex.encodeToString(resultCipherText, true);
						client.send(hexData[0]);
						client.stop();
						Main.showMsg(hexData[0]);//字符串密文
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}

				else if(flag[0]!=null&&flag[0].equals("request_id")){
					String[] id = new String[2];
					id = strArray[0].split(":");
					PrivateKey encryptPrivateKey;
					try {
						encryptPrivateKey = kgcMaster.getKgc().genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id[1], PrivateKeyType.KEY_ENCRYPT);
						byte[] ss = encryptPrivateKey.toByteArray();
						String hexss = Hex.encodeToString(ss, true);//字符串用户加密私钥
						
						SM9Curve curve = new SM9Curve();
						//用户加解密私钥
						PrivateKey encryptPrivateKey1 = PrivateKey.fromByteArray(curve, Hex.decode(hexss));
						int macKeyByteLen = SM3.DIGEST_SIZE;
						//密文
						ResultCipherText cipherText = ResultCipherText.fromByteArray(curve, Hex.decode(strArray[1]));		            
//		            	SM9Curve sm9Curve = new SM9Curve();
//		            	SM9 sm9 = new SM9(sm9Curve);
						printInfo(client, "Send Data123: " + id[1]);
						byte[] msgd = sm9.decrypt(cipherText, encryptPrivateKey, id[1], false, macKeyByteLen);
						String msgdStr = new String(msgd);
						printInfo(client, "Send Data123: " + msgdStr);
						client.send(msgdStr);
					} catch (Exception e) {
						// TODO Auto-generated catch block
						client.send("验证失败");
						printInfo(client, "验证失败");
						e.printStackTrace();
					}
				}
				}catch(Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
				

			@Override
			public void onDisconnect(SocketTransceiver client) {
				printInfo(client, "Disconnect");
			}

			@Override
			public void onServerStop() {
				System.out.println("--------Server Stopped--------");
			}
		};
		System.out.println("--------Server Started--------");
		server.start();
	}

	static void printInfo(SocketTransceiver st, String msg) {
		System.out.println("Client " + st.getInetAddress().getHostAddress());
		System.out.println("  " + msg);
	}

    public static void showMsg(String msg) {
        System.out.println(msg);
    }

}
