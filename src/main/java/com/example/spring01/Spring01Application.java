package com.example.spring01;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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
class MenuController {

	@GetMapping("/api/menu")
	public List<Map<String, String>> menu() {
		return Arrays.asList(menuItem("Home", "#/home"), menuItem("About", "#/about"));
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
				+ "<div class=\"container\"><span class=\"navbar-brand\">Menu</span><div id=\"menu\" class=\"navbar-nav\"></div></div></nav>"
				+ "<main class=\"container py-4\"><h1 id=\"title\"></h1><p id=\"content\"></p></main>"
				+ "<script>const pages = { '#/home': ['Home', 'Welcome.'], '#/about': ['About', 'About this application.'] };"
				+ "function render() { const route = location.hash || '#/home'; const page = pages[route] || ['Not found', 'Page not found.'];"
				+ "document.getElementById('title').textContent = page[0]; document.getElementById('content').textContent = page[1];"
				+ "document.querySelectorAll('#menu a').forEach(a => { const active = a.getAttribute('href') === route; a.classList.toggle('active', active); if (active) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }); }"
				+ "window.addEventListener('hashchange', render); render();"
				+ "fetch('/api/menu').then(r => { if (!r.ok) throw new Error('Menu unavailable'); return r.json(); }).then(items => {"
				+ "const menu = document.getElementById('menu'); items.forEach(item => { const a = document.createElement('a');"
				+ "a.className = 'nav-link'; a.href = item.route; a.textContent = item.label; menu.appendChild(a); }); render();"
				+ "}).catch(() => { document.getElementById('menu').textContent = 'Menu unavailable'; });</script></body></html>";
	}
}
