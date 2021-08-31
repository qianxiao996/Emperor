from selenium import webdriver
from selenium.webdriver.chrome.options import Options  # => 引入Chrome的配置


class Chrome_Screen:
    def __init__(self, chrome_driver, url):
        super(Chrome_Screen, self).__init__()
        self.chrome_driver = chrome_driver
        self.url = url

    def main(self):
        # 配置
        ch_options = Options()
        ch_options.add_argument("headless")  # => 为Chrome配置无头模式
        ch_options.add_argument("log-level=3")
        ch_options.add_argument('--incognito')  # 隐身模式（无痕模式）
        ch_options.add_argument('--ignore-certificate-errors')
        # 在启动浏览器时加入配置
        driver = webdriver.Chrome(chrome_options=ch_options,
                                  executable_path=self.chrome_driver)  # => 注意这里的参数
        driver.get(self.url)
        width = driver.execute_script("return document.documentElement.scrollWidth")
        height = driver.execute_script("return document.documentElement.scrollHeight")
        driver.set_window_size(width, height)
        # 只有截图才能看到效果咯
        # driver.save_screenshot('./ch.png')
        screen_img = driver.get_screenshot_as_base64()  # 此处为base64
        # print(screen_img)
        driver.quit()
        return screen_img
