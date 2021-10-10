<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
   <head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
		<title>登录</title>
	</head>
	<body>
	    
	
		<div style="text-align: center;" id="bg">  
			<div class='div_logo'>
				<p >用户登录</p>
			</div>
			
			<div class='div_form'>
				 
				<form name='login' action='servlet/LoginServlet' method='post'>
						<div class='div_login_input' id='user'>
							<div id='icon_user'></div>
							<input class='login' id='username' type='text' name='user_account' placeholder='用户名'></input>
							<span class='hint' id='hint_user'></span>
						</div>
						
						<div class='div_btn'>
							<input id='login_submit'  type='submit'  value='登录'></input>
						</div>
				</form>
		</div>
</body>
</html>