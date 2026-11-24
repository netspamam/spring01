package com.example.spring01;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@SpringBootApplication
public class Spring01Application {

	public static void main(String[] args) {
		SpringApplication.run(Spring01Application.class, args);
	}

}

@RestController
class AuthController {
	private static final String DB_URL = env("DB_URL", "jdbc:postgresql://localhost:5432/local?currentSchema=public");
	private static final String DB_USER = env("DB_USER", "postgres");
	private static final String DB_PASSWORD = env("DB_PASSWORD", "dfktyrb12");
	private static final String DEFAULT_JWT_SECRET = env("JWT_SECRET", "local-development-secret-key-32chars");
	private static final SecureRandom RANDOM = new SecureRandom();

	private static String env(String key, String fallback) {
		String value = System.getenv(key);
		return value == null || value.isBlank() ? fallback : value;
	}

	@PostMapping("/api/auth/register")
	public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
		String username = body.get("username");
		String password = body.get("password");
		if (username == null || username.isBlank() || password == null || password.length() < 8) {
			return ResponseEntity.badRequest().body(Map.of("error", "Username and password (at least 8 characters) are required"));
		}
		try (Connection connection = connection()) {
			createUsersTable(connection);
			byte[] salt = new byte[16];
			RANDOM.nextBytes(salt);
			try (PreparedStatement statement = connection.prepareStatement(
					"INSERT INTO public.app_users (username, password_salt, password_hash) VALUES (?, ?, ?)")) {
				statement.setString(1, username);
				statement.setBytes(2, salt);
				statement.setBytes(3, passwordHash(password, salt));
				statement.executeUpdate();
			}
			return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("token", issueToken(username)));
		} catch (java.sql.SQLException e) {
			if ("23505".equals(e.getSQLState())) return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "Username already exists"));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Database unavailable"));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Authentication configuration error"));
		}
	}

	@PostMapping("/api/auth/login")
	public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
		String username = body.get("username");
		String password = body.get("password");
		if (username == null || password == null) return ResponseEntity.badRequest().body(Map.of("error", "Username and password are required"));
		try (Connection connection = connection()) {
			createUsersTable(connection);
			try (PreparedStatement statement = connection.prepareStatement(
					"SELECT password_salt, password_hash FROM public.app_users WHERE username = ?")) {
				statement.setString(1, username);
				try (ResultSet result = statement.executeQuery()) {
					if (!result.next()) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Пользователь не найден"));
					if (!MessageDigest.isEqual(result.getBytes("password_hash"), passwordHash(password, result.getBytes("password_salt")))) {
						return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Неверный пароль"));
					}
				}
			}
			return ResponseEntity.ok(Map.of("token", issueToken(username)));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Database or authentication configuration error"));
		}
	}

	private static Connection connection() throws java.sql.SQLException {
		try {
			Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
			System.out.println("Статус подключения к PostgreSQL: подключено");
			return connection;
		} catch (java.sql.SQLException e) {
			System.out.println("Статус подключения к PostgreSQL: ошибка подключения — " + e.getMessage());
			throw e;
		}
	}

	private static void createUsersTable(Connection connection) throws java.sql.SQLException {
		try (Statement statement = connection.createStatement()) {
			statement.execute("CREATE TABLE IF NOT EXISTS public.app_users (username VARCHAR(100) PRIMARY KEY, password_salt BYTEA NOT NULL, password_hash BYTEA NOT NULL)");
		}
	}

	private static byte[] passwordHash(String password, byte[] salt) throws Exception {
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 120000, 256);
		try {
			return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
		} finally {
			spec.clearPassword();
		}
	}

	private static String issueToken(String username) throws Exception {
		String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
		String subject = Base64.getUrlEncoder().withoutPadding().encodeToString(username.getBytes(StandardCharsets.UTF_8));
		String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"sub\":\"" + subject + "\",\"exp\":" + (System.currentTimeMillis() / 1000 + 3600) + "}").getBytes(StandardCharsets.UTF_8));
		String content = header + "." + payload;
		return content + "." + sign(content);
	}

	static boolean validToken(String token) {
		try {
			String[] parts = token.split("\\.");
			if (parts.length != 3 || !MessageDigest.isEqual(sign((parts[0] + "." + parts[1])).getBytes(StandardCharsets.US_ASCII), parts[2].getBytes(StandardCharsets.US_ASCII))) return false;
			String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
			java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\\\"exp\\\":(\\d+)").matcher(payload);
			return matcher.find() && Long.parseLong(matcher.group(1)) > System.currentTimeMillis() / 1000;
		} catch (Exception e) {
			return false;
		}
	}

	private static String sign(String content) throws Exception {
		String secret = DEFAULT_JWT_SECRET;
		if (secret.length() < 32) secret = "local-development-secret-key-32chars";
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(content.getBytes(StandardCharsets.US_ASCII)));
	}
}

@Configuration
class JwtAuthorizationConfiguration implements WebMvcConfigurer {
	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(new HandlerInterceptor() {
			@Override
			public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
				String authorization = request.getHeader("Authorization");
				if (authorization != null && authorization.startsWith("Bearer ") && AuthController.validToken(authorization.substring(7))) return true;
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.setContentType("application/json");
				response.getWriter().write("{\"error\":\"Bearer token required\"}");
				return false;
			}
		}).addPathPatterns("/api/menu");
	}
}

@RestController
class MenuController {

	@GetMapping("/api/menu")
	public List<Map<String, String>> menu() {
		return Arrays.asList(menuItem("Home", "#/home"), menuItem("About", "#/about"), menuItem("Settings", "#/settings"));
	}

	private Map<String, String> menuItem(String label, String route) {
		Map<String, String> item = new LinkedHashMap<>();
		item.put("label", label);
		item.put("route", route);
		return item;
	}

	@GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
	public String index() {
		return "<!doctype html><html lang=\"en\"><head>"
				+ "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
				+ "<title>Menu</title><link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">"
				+ "</head><body><nav class=\"navbar navbar-expand navbar-dark bg-dark\" aria-label=\"Main navigation\">"
				+ "<div class=\"container\"><span class=\"navbar-brand\">Menu</span><div id=\"menu\" class=\"navbar-nav me-auto\"></div>"
				+ "<button id=\"logout\" class=\"btn btn-outline-light btn-sm d-none\" type=\"button\">Logout</button></div></nav>"
				+ "<main class=\"container py-4\"><h1 id=\"title\"></h1><p id=\"content\"></p>"
				+ "<section id=\"auth\" class=\"card p-3 mt-3\" style=\"max-width:400px\"><h2 class=\"h5\">Authorization</h2>"
				+ "<form id=\"authForm\"><div class=\"mb-2\"><input id=\"username\" class=\"form-control\" placeholder=\"Username\" autocomplete=\"username\" required></div>"
				+ "<div class=\"mb-3\"><input id=\"password\" type=\"password\" class=\"form-control\" placeholder=\"Password (at least 8 characters)\" autocomplete=\"current-password\" required minlength=\"8\"></div>"
				+ "<button class=\"btn btn-primary me-2\" type=\"submit\">Login</button><button id=\"register\" class=\"btn btn-secondary\" type=\"button\">Register</button>"
				+ "<div id=\"authError\" class=\"text-danger mt-2\"></div></form></section></main>"
				+ "<script>const pages = { '#/home': ['Home', 'Welcome.'], '#/about': ['About', 'About this application.'], '#/settings': ['Settings', 'Application settings.'] };"
				+ "function render() { const route = location.hash || '#/home'; const page = pages[route] || ['Not found', 'Page not found.'];"
				+ "document.getElementById('title').textContent = page[0]; document.getElementById('content').textContent = page[1];"
				+ "document.querySelectorAll('#menu a').forEach(a => { const active = a.getAttribute('href') === route; a.classList.toggle('active', active); if (active) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }); }"
				+ "async function loadMenu() { const token = localStorage.getItem('token'); const error = document.getElementById('authError');"
				+ "if (!token) { document.getElementById('auth').classList.remove('d-none'); document.getElementById('logout').classList.add('d-none'); return; }"
				+ "document.getElementById('auth').classList.add('d-none'); document.getElementById('logout').classList.remove('d-none');"
				+ "try { const response = await fetch('/api/menu', { headers: { 'Authorization': 'Bearer ' + token } });"
				+ "if (response.status === 401) { localStorage.removeItem('token'); document.getElementById('menu').replaceChildren(); document.getElementById('auth').classList.remove('d-none'); document.getElementById('logout').classList.add('d-none'); error.textContent = 'Session expired'; return; }"
				+ "if (!response.ok) throw new Error('Menu unavailable'); const items = await response.json(); const menu = document.getElementById('menu'); menu.replaceChildren();"
				+ "items.forEach(item => { const a = document.createElement('a'); a.className = 'nav-link'; a.href = item.route; a.textContent = item.label; menu.appendChild(a); }); render(); }"
				+ "catch (e) { error.textContent = e.message; } }"
				+ "async function authenticate(url) { const username = document.getElementById('username').value.trim(); const password = document.getElementById('password').value; const error = document.getElementById('authError');"
				+ "error.textContent = ''; try { const response = await fetch(url, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({username, password}) }); const data = await response.json();"
				+ "if (!response.ok) throw new Error(data.error || 'Authorization failed'); localStorage.setItem('token', data.token); document.getElementById('authForm').reset(); await loadMenu(); } catch (e) { error.textContent = e.message; } }"
				+ "document.getElementById('authForm').addEventListener('submit', event => { event.preventDefault(); authenticate('/api/auth/login'); });"
				+ "document.getElementById('register').addEventListener('click', () => authenticate('/api/auth/register'));"
				+ "document.getElementById('logout').addEventListener('click', () => { localStorage.removeItem('token'); document.getElementById('menu').replaceChildren(); loadMenu(); });"
				+ "window.addEventListener('hashchange', render); render(); loadMenu();</script></body></html>";
	}
}
