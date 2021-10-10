package servlet;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.sql.*;
import java.util.Random;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.service.ClsMainClient;
import com.service.Parameter_tran;

/**
 * Servlet implementation class LoginServlet
 */
@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public LoginServlet() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		//获取到移动端的数据
		// TODO Auto-generated method stub
		if (request.getParameter("plaintext") != null && request.getParameter("sid") != null) {
			String sid = request.getParameter("sid");
			String rPlaintext = request.getParameter("plaintext");
			System.out.println("rPlaintext = " + new String(rPlaintext.getBytes("ISO8859-1"), "UTF-8"));
			try {
				Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
			} catch (ClassNotFoundException e) {
				System.err.println("error");
			}
			Connection connection = null;
			String plaintext_sql = "select plaintext from record where sid='" + sid + "';";
			try {
				connection = DriverManager.getConnection("jdbc:sqlserver://127.0.0.1:1433;databaseName=data", "sa",
						"123456");
				// 连接数据库对象
				Statement stat = connection.createStatement();
				ResultSet rs = stat.executeQuery(plaintext_sql);
				if (rs.next()) {
					String plaintext = rs.getString("plaintext");
					connection.createStatement();
					System.out.println("plaintext = " + new String(plaintext.getBytes("ISO8859-1"), "UTF-8"));
					if(plaintext.equals(rPlaintext)) {

						System.out.println("验证成功");
					
						PreparedStatement psm = connection.prepareStatement("update record set flag=1 where sid=?");
						psm.setString(1, sid);
						psm.executeUpdate();
						connection.createStatement();
						connection.close();
					}
					else {
						//System.out.println("验证失败");
					}
					connection.close();
				}
			} catch (SQLException e) {
				e.printStackTrace();
				System.out.print(e.getErrorCode());
				System.exit(0);
			}
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		//加入新请求
		// TODO Auto-generated method stub

		if (request.getMethod().equalsIgnoreCase("post")) {
			if (request.getParameter("user_account") != null) {
				String user_account = request.getParameter("user_account");
				String sid = request.getSession().getId();
				BigInteger b = new BigInteger(128, new Random());

				try {
					Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
				} catch (ClassNotFoundException e) {
					System.err.println("error");
				}
				Connection connection = null;
				String id_sql = "select id from record where sid='" + sid + "';";
				String sql = "insert into record values" + "(?,?,?,?)";
				String update_sql = "update record set plaintext=? where id=?";
				PreparedStatement psm = null;
				int max;
				String sql_max = "select id from record where id=(select MAX(id) from record )";
				ResultSet rs = null;
				Statement stat;
				try {
					connection = DriverManager.getConnection("jdbc:sqlserver://127.0.0.1:1433;databaseName=data", "sa",
							"123456");
					// 连接数据库对象
					stat = connection.createStatement();
					rs = stat.executeQuery(id_sql);
					if (rs.next()) {
						int id = rs.getInt("id");
						psm = connection.prepareStatement(update_sql);
						psm.setString(1, b.toString());
						psm.setLong(2, id);
						psm.executeUpdate();
						connection.createStatement();
						connection.close();

						psm.close();
					} else {
						rs = stat.executeQuery(sql_max);
						if (rs.next()) {
							max = rs.getInt("id") + 1;
							rs.close();
							stat.close();
						} else
							max = 1;
						psm = connection.prepareStatement(sql);
						psm.setLong(1, max);
						psm.setString(2, sid);
						psm.setString(3, b.toString());
						psm.setInt(4, 0);
						psm.executeUpdate();
						connection.createStatement();
						connection.close();
						psm.close();
					}
				} catch (SQLException e) {
					e.printStackTrace();
					System.out.print(e.getErrorCode());
					System.exit(0);
				}

				ClsMainClient cls = new ClsMainClient();
				System.out.print(b);
				cls.conn("127.0.0.1", 12332, user_account, b.toString());
				Parameter_tran p = new Parameter_tran();
				String encrypt_str = p.getEncrypt_str();
//			System.out.print(request.getSession().getId());
				request.getSession().setAttribute("encrypt_str", encrypt_str);
				request.getSession().setAttribute("name", user_account);
				response.sendRedirect("/register/scan.jsp");
			}
		}
	}
}
