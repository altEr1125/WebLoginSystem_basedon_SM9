<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8" />
		<title></title>
	</head>
	<body>
		<script type="text/javascript" src="js/jquery-1.8.3.min.js" ></script>
		<script type="text/javascript" src="js/jquery.qrcode.js" ></script>
        <script type="text/javascript" src="js/qrcode.js" ></script> 
        <script type="text/javascript" src="js/utf.js" ></script>
        <div  id="qrcodeTable">
			<p>--- 请使用登陆助手app扫描下方二维码进行身份认证 ---</p>
			<p>
				<%
					String name = session.getAttribute("name").toString();
				%>
				登录名：<%=name%>
			</p>
			</div>
			<script> 
				 var s='<%=session.getAttribute("encrypt_str")%>';
				var sid='<%=session.getId()%>';
				var webServerURL="http://172.20.10.4:8080/register/servlet/LoginServlet";
				var name='<%=session.getAttribute("name")%>';
				var id='<%=session.getAttribute("name")%>';
			var str = "encrypt_str:" + s + ";sid:" + sid + ";webServerURL:"
					+ webServerURL + ";name:" + name + ";id:" + id;
			jQuery('#qrcodeTable').qrcode({
				render : "table", //二维码生成方式
				text : str, //二维码内容
				width : "230", //二维码的宽度
				height : "230",
			});
			/*  jQuery('#qrcodeCanvas').qrcode({
				  render    : "canvas",
				 text    : "http://www.baidu.com",
				 width : "200",               //二维码的宽度
				 height : "200",              //二维码的高度
				 background : "#ffffff",       //二维码的后景色
				 foreground : "#000000",        //二维码的前景色
				 src: 'img/gray.jpg'             //二维码中间的图片
			 });     */
		</script>
			<form name='login' action='servlet/LoginServlet' method='post'>
				<input type='hidden' id='username' type='text' name='user_account'
					value=<%=name%>></input> <input type="button" onclick="back()"
					value="返回" /> <input id='login_submit' type='submit' value='刷新二维码'></input>
			</form>
			<script>
			function back() {
				var url = "http://localhost:8080/register/login.jsp";
				window.location.href = url;
			}
		</script>
		
		<script language="javascript">
function getData() {
window.location.href = "servlet/CheckServlet";
}
</script>
 <BODY onload="getData()">

    			 </body>
		<script type="text/javascript">
var websocket=null;
//判断浏览器是否支持websocket
if('WebSocket' in window){
	websocket=new WebSocket("ws://localhost:8080/WebSocket/server");
	websocket.onopen=function(){
		websocket.send("客户端连接成功");
	}
	websocket.onerror=function(){
		websocket.send("客户端连接失败");
	}
	websocket.onclose=function(){
		websocket.send("客户端连接关闭");
	}
	websocket.onmessage=function(e){
		send(e.data);
	}
	//监听窗口关闭事件，当窗口关闭时，主动去关闭websocket连接，防止连接还没断开就关闭窗口，server端会抛异常。
	window.onbeforeunload = function () {
	    closeWebSocket();
	}
}
else {
    alert('当前浏览器 Not support websocket')
}
//将消息显示在网页上
function send(e) {
    var obj = eval("("+e+")");  
    document.getElementById('price').innerHTML =obj.price;
    document.getElementById('total').innerHTML = obj.total;
}
//关闭WebSocket连接
function closeWebSocket() {
    websocket.close();
}
</script>
</html>
