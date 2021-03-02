package ch.m183.session;

import static org.aspectj.bridge.MessageUtil.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import lombok.extern.java.Log;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;

/**
 * e2e smoke tests
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Log
class SessionApplicationTests {
	@LocalServerPort
	private int port;

	@Test
	void contextLoads_successful() {
		smokeGetAndVerifyResponseStatus("/", HttpURLConnection.HTTP_OK);
	}

	@Test
	void h2console_isAccessible() {
		smokeGetAndVerifyResponseStatus("/h2-console/", HttpURLConnection.HTTP_OK);
	}

	// a424fec295f1efb97376e5d17138e5a1 TODO we should remove the JSESSIONID
	//  @Test
	void sessionId_shouldNotBeExposingFramework() {
		String merge = getCookies("/login").stream().map(HttpCookie::toString).collect(Collectors.joining(""));
		assertFalse(merge.toUpperCase().contains("JSESSIONID"), "JSESSIONID FOUND ");
	}

	private List<HttpCookie> getCookies(String path) {
		try {
			CookieManager cookieManager = new CookieManager();
			CookieHandler.setDefault(cookieManager);
			URL url = new URL(getUrl(path));
			URLConnection connection = url.openConnection();
			connection.getContent();
			List<HttpCookie> cookies = cookieManager.getCookieStore().getCookies();
			return cookies;

		} catch (IOException e) {
			fail(e.getMessage());
		}
		return new ArrayList<>();
	}

	private void smokeGetAndVerifyResponseStatus(String path, int responseCode) {
		try {
			URL url = new URL(getUrl(path));
			HttpURLConnection con = null;
			try {
				con = get(url);
				assertEquals(responseCode, con.getResponseCode());
			} finally {
				if (con != null) {
					con.disconnect();
				}
			}

		} catch (IOException e) {
			fail(e.getMessage());
		}
	}

	private HttpURLConnection get(URL url) throws IOException {
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("GET");
		con.setConnectTimeout(2000);
		con.setReadTimeout(2000);
		return con;
	}

	private String getUrl(String path) {
		return "http://localhost:" + port + path;
	}
}
