package servlet;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class checkServlet
 */
@WebServlet("/checkServlet")
public class CheckServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public CheckServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		String sid = request.getParameter("sid");
		try {
			Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
		} catch (ClassNotFoundException e) {
			System.err.println("error");
		}
		Connection connection = null;
		String flag_sql = "select flag from record where sid='" + sid + "';";
		try {
			connection = DriverManager.getConnection("jdbc:sqlserver://127.0.0.1:1433;databaseName=data", "sa",
					"123456");
			// 连接数据库对象
			Statement stat = connection.createStatement();
			ResultSet rs = stat.executeQuery(flag_sql);
			if (rs.next()) {
				int flag = rs.getInt("flag");
				connection.createStatement();
				if(flag==1) {
					PreparedStatement psm = connection.prepareStatement("delete from record where sid=?");
					psm.setString(1, sid);
					psm.executeUpdate();
					connection.createStatement();
					connection.close();
					request.getSession().setAttribute("name", request.getParameter("user_account"));
					response.sendRedirect("/register/loginSuccess.jsp");
				}
				else {
					//System.out.println("验证失败");
					response.sendRedirect("/register/scan.jsp");
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
