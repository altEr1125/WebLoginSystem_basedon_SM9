package com.dommy.qrcode;

import android.Manifest;
import android.app.AlertDialog;
import android.content.ContentValues;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.StrictMode;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.dommy.qrcode.util.Constant;
import com.google.zxing.activity.CaptureActivity;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;


public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    Button btnQrCode; // 扫码
    TextView tvResult; // 结果
    TextView writeRes; // 将结果写到发送框

    private Button bnConnect;
    private TextView txReceive;
    private EditText edIP, edPort, edData;
    String id = "2373721226@qq.com";
    String hostIP;
    String res;
    String encrypt_str,sid,webServerURL,rName,rId;


    private Handler handler = new Handler(Looper.getMainLooper());

    private TcpClient client = new TcpClient() {

        @Override
        public void onConnect(SocketTransceiver transceiver) {
            refreshUI(true);
        }

        @Override
        public void onDisconnect(SocketTransceiver transceiver) {
            refreshUI(false);
        }

        @Override
        public void onConnectFailed() {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(MainActivity.this, "连接失败",
                            Toast.LENGTH_SHORT).show();
                }
            });
        }

        @Override
        public void onReceive(SocketTransceiver transceiver, final String s) {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    txReceive.append(s+'\n');
                    res = s;
                    if(!res.equals("验证失败"))
                        sendStr(res);
                    String str = webServerURL+"?sid=" + sid + "&plaintext=" + res;
                    sendStr(str);
                    StringBuilder url = new StringBuilder(str);

                    HttpURLConnection conn = null;
                    try {
                        conn = (HttpURLConnection)new URL(url.toString()).openConnection();
                        conn.setConnectTimeout(5000);
                        conn.setRequestMethod("GET");
                        if(conn.getResponseCode() == 200){
                            Toast.makeText(MainActivity.this, "urlconnetc成功",
                                    Toast.LENGTH_SHORT).show();
                        }
                    } catch (IOException e) {
                        Toast.makeText(MainActivity.this, "urlconnetc失败",
                                Toast.LENGTH_SHORT).show();
                        e.printStackTrace();
                    }
                }
            });
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if (android.os.Build.VERSION.SDK_INT > 9) {
            StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
            StrictMode.setThreadPolicy(policy);
        }
        this.findViewById(R.id.bn_send).setOnClickListener(this);
        bnConnect = (Button) this.findViewById(R.id.bn_connect);
        bnConnect.setOnClickListener(this);

        edIP = (EditText) this.findViewById(R.id.ed_ip);
        edPort = (EditText) this.findViewById(R.id.ed_port);
        edData = (EditText) this.findViewById(R.id.ed_dat);
        txReceive = (TextView) this.findViewById(R.id.tx_receive);
        txReceive.setOnClickListener(this);
        refreshUI(false);
        initView();

    }

    private void initView() {
        btnQrCode = (Button) findViewById(R.id.btn_qrcode);
        btnQrCode.setOnClickListener(this);

        tvResult = (TextView) findViewById(R.id.txt_result);
        writeRes = (TextView) findViewById(R.id.ed_dat);
    }

    // 开始扫码
    private void startQrCode() {
        // 申请相机权限
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            // 申请权限
            ActivityCompat.requestPermissions(MainActivity.this, new String[]{Manifest.permission.CAMERA}, Constant.REQ_PERM_CAMERA);
            return;
        }
        // 申请文件读写权限
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            // 申请权限
            ActivityCompat.requestPermissions(MainActivity.this, new String[]{Manifest.permission.READ_EXTERNAL_STORAGE}, Constant.REQ_PERM_EXTERNAL_STORAGE);
            return;
        }
        // 二维码扫码
        Intent intent = new Intent(MainActivity.this, CaptureActivity.class);
        startActivityForResult(intent, Constant.REQ_QR_CODE);
    }



    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        //扫描结果回调
        if (requestCode == Constant.REQ_QR_CODE && resultCode == RESULT_OK) {
            Bundle bundle = data.getExtras();
            String scanResult = bundle.getString(Constant.INTENT_EXTRA_KEY_QR_SCAN);
            String[] strArray = new String[5];
            strArray = scanResult.split(";");
            encrypt_str = strArray[0].split(":",2)[1];
            sid = strArray[1].split(":",2)[1];
            webServerURL = strArray[2].split(":",2)[1];
            rName = strArray[3].split(":",2)[1];
            rId = strArray[4].split(":",2)[1];

            //将扫描出的信息显示出来
            tvResult.setText(scanResult);
//            writeRes.setText("id:2373721226@qq.com;"+strArray[0]);
            if(rId.equals(id)) {
                writeRes.setText("request_id:" + id);
                makedb(scanResult);
                if (!client.isConnected()) {
                    try {
                        hostIP = edIP.getText().toString();
                        int port = Integer.parseInt(edPort.getText().toString());
                        client.connect(hostIP, port);
                    } catch (NumberFormatException e) {
                        e.printStackTrace();
                    }
                }
                //请求公共参数
                sendStr("request_id:" + id + ";" + encrypt_str);
            }
            else{
                Toast.makeText(MainActivity.this, "登陆验证失败",
                        Toast.LENGTH_SHORT).show();
            }
        }
    }

    public void makedb(String scanResult){
        //调用DBOpenHelper
        DBOpenHelper helper = new DBOpenHelper(this,"pair.db",null,1);
        SQLiteDatabase db = helper.getWritableDatabase();
        //根据扫描的数据去数据库中进行查询
        Cursor c = db.query("user_tb",null,"userID=?",new String[]{scanResult},null,null,null);
        //如果有查询到数据，则说明账号已存在
        if(c!=null && c.getCount() >= 1){
//            Toast.makeText(this, "该用户已存在", Toast.LENGTH_SHORT).show();
            c.close();
        }
        //如果没有查询到数据，则往数据库中insert一笔数据
        else{
            //insert data
            ContentValues values= new ContentValues();
            values.put("userID",scanResult);
            long rowid = db.insert("user_tb",null,values);
//            Toast.makeText(this, "注册成功", Toast.LENGTH_SHORT).show();//提示信息

        }
        db.close();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode) {
            case Constant.REQ_PERM_CAMERA:
                // 摄像头权限申请
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    // 获得授权
                    startQrCode();
                } else {
                    // 被禁止授权
                    Toast.makeText(MainActivity.this, "请至权限中心打开本应用的相机访问权限", Toast.LENGTH_LONG).show();
                }
                break;
            case Constant.REQ_PERM_EXTERNAL_STORAGE:
                // 文件读写权限申请
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    // 获得授权
                    startQrCode();
                } else {
                    // 被禁止授权
                    Toast.makeText(MainActivity.this, "请至权限中心打开本应用的文件读写权限", Toast.LENGTH_LONG).show();
                }
                break;
        }
    }
    @Override
    public void onStop() {
        client.disconnect();
        super.onStop();
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.bn_connect:
                connect();
                break;
            case R.id.bn_send:
                sendStr();
                break;
            case R.id.tx_receive:
                clear();
                break;
            case R.id.btn_qrcode:
                startQrCode();
                break;
        }
    }

    /**
     * 刷新界面显示
     *
     * @param isConnected
     */
    private void refreshUI(final boolean isConnected) {
        handler.post(new Runnable() {
            @Override
            public void run() {
                edPort.setEnabled(!isConnected);
                edIP.setEnabled(!isConnected);
                bnConnect.setText(isConnected ? "断开" : "连接");
            }
        });
    }

    /**
     * 设置IP和端口地址,连接或断开
     */
    private void connect() {
        if (client.isConnected()) {
            // 断开连接
            client.disconnect();
        } else {
            try {
                String hostIP = edIP.getText().toString();
                int port = Integer.parseInt(edPort.getText().toString());
                client.connect(hostIP, port);
            } catch (NumberFormatException e) {
                Toast.makeText(this, "端口错误", Toast.LENGTH_SHORT).show();
                e.printStackTrace();
            }
        }
    }

    /**
     * 发送数据
     */
    private void sendStr() {
        try {
            String data = edData.getText().toString();
            client.getTransceiver().send(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private void sendStr(String data) {
        try {
            Thread.currentThread().sleep(500);
            client.getTransceiver().send(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 清空接收框
     */
    private void clear() {
        new AlertDialog.Builder(this).setTitle("确认清除?")
                .setNegativeButton("取消", null)
                .setPositiveButton("确认", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        txReceive.setText("");
                    }
                }).show();
    }
}
