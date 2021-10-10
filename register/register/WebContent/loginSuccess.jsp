<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
<div tyle="text-align: center;">
<%
					String name = session.getAttribute("name").toString();
				%>
				<h1>登陆成功</h1>
				当前登录用户：<%=name%>
				</div>
</body>
</html>