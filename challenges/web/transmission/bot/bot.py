import sys
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoAlertPresentException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
import urllib.parse

seen_links = set()

def log(message, level="INFO"):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] [{level}] {message}\n"
    sys.stdout.write(full_message)
    sys.stdout.flush()


seen_links = set()

def process_page(driver):
    try:
        log("Processing page...")

        admin_url = "http://172.20.0.2:5000/admin"
        driver.get(admin_url)

        driver.add_cookie({"name": "flag", "value": "LABO{EtRaNg3_C3_l1eN_Y0u7UB3}"})

        driver.get(admin_url)
        time.sleep(1)

        links = driver.find_elements(By.TAG_NAME, "a")

        new_links_found = False

        for i in range(len(links)):
            driver.get(admin_url)
            time.sleep(1)
            links = driver.find_elements(By.TAG_NAME, "a")

            if i >= len(links):
                break

            link = links[i]
            uuid_text = link.text.strip()

            if uuid_text in seen_links:
                continue  

            seen_links.add(uuid_text)
            new_links_found = True

            href = link.get_attribute("href")
            outer_html = link.get_attribute("outerHTML")
            log(f"Link is: {outer_html}")
            print(f"[+] Found link: {href}")

            if href.startswith("javascript:"):
                log(f"[*] Clicking on JavaScript link ({uuid_text})...")
                try:
                    driver.execute_script("arguments[0].scrollIntoView(true);", link)
                    time.sleep(0.2)
                    link.click()
                    time.sleep(2)
                except Exception as e:
                    log(f"[!] JS link click failed: {e}", "WARNING")
            else:
                log(f"[*] Visiting normal link in new tab: {href}")
                driver.switch_to.new_window("tab")
                try:
                    driver.get(href)
                    driver.add_cookie({"name": "flag", "value": "LABO{EtRaNg3_C3_l1eN_Y0u7UB3}"})
                    time.sleep(2)
                except Exception as e:
                    log(f"[!] Error visiting URL: {e}", "WARNING")
                finally:
                    driver.close()
                    driver.switch_to.window(driver.window_handles[0])

        if not new_links_found:
            log("No new links to process. Returning to main loop.")
            return

    except Exception as e:
        log(f"Page processing error: {str(e)}", "ERROR")

def main_loop():
    while True:
        driver = None
        try:
            options = webdriver.ChromeOptions()
            
            options.add_argument('--disable-web-security')
            options.add_argument('--disable-site-isolation-trials')
            options.add_argument('--disable-features=SameSiteByDefaultCookies')
            
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            
            options.add_argument("--disable-xss-auditor")
            
            service = Service(
                ChromeDriverManager().install(),
                service_args=['--verbose']
            )
            
            driver = webdriver.Chrome(service=service, options=options)
            driver.implicitly_wait(15)

            test = driver.get("http://172.20.0.2:5000/admin")
            log(driver.current_url.lower())
            if "admin" in driver.current_url.lower():
                try:
                    username = driver.find_element(By.NAME, "username")
                    password = driver.find_element(By.NAME, "password")
                    
                    username.send_keys("admin")
                    password.send_keys("jVYmJ^LnDz$fu9&d%AXiDRBtD@j#xk")
                    password.submit()
                    time.sleep(3)
                    
                    if "login" in driver.current_url.lower():
                        log("Login failed", "ERROR")
                        return
                        
                except WebDriverException as e:
                    log(f"Login error: {str(e)}", "ERROR")
                    return
            
            process_page(driver)
            
        except Exception as e:
            log(f"Main loop error: {str(e)}", "ERROR")
            
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception as e:
                    log(f"Driver quit error: {str(e)}", "WARNING")
            
            log("Sleeping for 60 seconds...")
            time.sleep(60)

if __name__ == "__main__":
    log("Starting XSS Challenge Bot")
    try:
        main_loop()
    except KeyboardInterrupt:
        log("Bot stopped by user")
    except Exception as e:
        log(f"Fatal error: {str(e)}", "CRITICAL")
