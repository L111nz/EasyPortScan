import tkinter as tk
import socket
import threading
import sys
import queue
import time
import threadpool
import IPy
from ipaddress import ip_address

# 端口扫描
# 指定ip段和端口范围 第9组

class GUI():
	'''
	界面类
	'''
	def __init__(self, window):
		self.msg_queue = queue.Queue()

		self.initGUI(window)


	def initGUI(self, window):
		self.window = window


		self.window.resizable(0,0)
		self.window.geometry('550x300+500+200')

		self.ip = tk.Label(self.window, text="地址", font=('Arial', 13))
		self.ip.place(x=5, y=8)
		self.port = tk.Label(self.window, text="端口", font=('Arial', 13))
		self.port.place(x=240, y=8)
		self.thread = tk.Label(self.window, text="线程", font=('Arial', 13))
		self.thread.place(x=360, y=8)
		self.ips = tk.Text(self.window, height=1, width=23, font=('', 13))
		self.ips.place(x=43, y=7)
		self.ports = tk.Text(self.window, height=1, width=9, font=('', 13))
		self.ports.place(x=274, y=7)
		self.threads = tk.Text(self.window, height=1, width=5, font=('', 13))
		self.threads.place(x=400, y=7)

		self.scan = tk.Button(self.window, text='扫描', height=1, command=self.show)

		self.scan.place(x=460, y=4)

		self.show = tk.Text(self.window, height=14, width=59, fg="#06EB00", bg='black', state='disabled',font=('', 15))

		self.show.place(x=3, y=33)

		self.window.after(100, self.show_msg)
		
		sys.stdout = ReText(self.msg_queue)

		self.window.mainloop()


	def show_msg(self):
		while not self.msg_queue.empty():
			content = self.msg_queue.get()
			self.show.config(state="normal")
			self.show.insert('end', content)
			self.show.see('end')
			self.show.config(state="disabled")

		self.window.after(100, self.show_msg)

	def show(self):
		# T = threading.Thread(target=PortScan.main, args=(PortScan,))
		T = threading.Thread(target=start, args=(self.ips.get("1.0", "end"), self.ports.get("1.0", "end"),
												self.threads.get("1.0", "end"),))

		T.start()



class ReText():
	def __init__(self, queue):
		self.queue = queue

	def write(self, content):
		self.queue.put(content)


class PortScan(threading.Thread):
	'''
	端口扫描类：
	'''
	def __init__(self, port_queue, ip, timeout = 3):
		# 规范化 三个成员变量均加上__为私有变量
		threading.Thread.__init__(self)
		self.__port_queue = port_queue
		self.ip = ip
		self.__timeout = timeout

	# 实现线程方法run
	def run(self):
		'''
		多线程实际调用的方法，如果端口队列不为空，循环执行
		'''
		while True:
			if self.__port_queue.empty():
				break

			# OPEN_MSG = "% 6d [OPEN]\n"
			port = self.__port_queue.get(timeout=0.5)
			ip = self.ip
			timeout = self.__timeout

			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(timeout)
				result_code = s.connect_ex((ip, port))  # 开放放回0
				if result_code == 0:
					sys.stdout.write(f'{ip}  {port}[开放]\n')

				# result_list.append(port)
				# else:
				#      sys.stdout.write("% 6d [CLOSED]\n" % port)

			except Exception as e:
				print(e)
			finally:
				s.close()

		# time.sleep(3)
		# if self.__port_queue.empty():
		# 	sys.stdout.write('[+] 扫描完成')

# 获取端口 start_port - end_port
def get_port_list(port):
	'''
	返回扫描的端口list：
	'''
	# port = '1-80'
	if port == '':
		return list(range(1, 65535 + 1))  # range(1,65535)表示1-65534，因此end_port要加1
	else:
		is_ports = port.find('-')
		if is_ports != -1:
			port_arr = port.split('-')
			start_port = port_arr[0]
			start_port = int(start_port)
			end_port = port_arr[1]
			end_port = int(end_port)
			if start_port >= 1 and end_port <= 65535 and start_port <= end_port:
				return list(range(start_port, end_port + 1))  # range(1,65535)表示1-65534，因此end_port要加1
			else:
				print('[-] 端口范围有错')
		else:
			return port

# 检查ip合法性
def check_ip(ip):
	try:
		IPy.IP(ip)
		return True
	except Exception as e:
		print(e)
		return False

# 获取 ip
def get_ip_list(ip):
	'''
	对传入对ip进行识别，判断合法性，以及判断是单个ip还是ip段
	'''
	is_ips = ip.find('-')	# 是否是ip段
	# print(type(is_ips))

	if is_ips != -1:
		# print('ip段')
		ip_list = []
		ip_arr = ip.split('-')
		start_ip = ip_address(ip_arr[0])
		end_ip = ip_address(ip_arr[1])
		if check_ip(ip_arr[0]) and check_ip(ip_arr[1]):
			while start_ip <= end_ip:
				ip_list.append(str(start_ip))
				start_ip += 1
			return ip_list
		else:
			print('[-] ip不合法')
		# if ip_arr[1] == '24':
		# 	# print(ip_arr[0])  # 10.101.144.0 ，传入即可
		# 	if check_ip(ip_arr[0]):
		# 		tmp = ip_arr[0].split('.')
		# 		print(int(tmp[3]))
		#
		# 		for i in range(0, 256):
		# 			ip_queue.put(int(tmp[3]) + i)
		#
		# 			# print(int(tmp[3]) + i)

	else:
		# print('单个ip')
		if check_ip(ip):
			ip_list = []
			ip_list.append(ip)
			return ip_list
		else:
			print('[-] ip不合法')

# 绑定按钮的事件
def start(ip, port, thread_num):

	ip_arr = ip.split('\n')
	ip = ip_arr[0]

	ip_list = get_ip_list(ip)

	for ip in ip_list:
		print(ip)
		main(ip, port,thread_num)


# 主方法
def main(ip, port, thread_num):
	port_queue = queue.Queue()  # 配合多线程
	threads = []  # 保存新线程
	# ip = "10.101.144.50"

	# 从ui获取的变量会带个换行符，需要将\n去掉
	ip_arr = ip.split('\n')
	ip = ip_arr[0]

	# ip_list = get_ip_list(ip)

	port_arr = port.split('\n')
	port = port_arr[0]

	# thread_num = 10  # 线程数，测试完成后改为从ui获取
	port_list = get_port_list(port)
	# print(port_list)

	for i in port_list:
		port_queue.put(i)

	for i in range(int(thread_num)):
		threads.append(PortScan(port_queue, ip, 1))
	print(f"[+] {ip} {port}")
	print("[+] 开始执行")

	# 启动线程
	for thread in threads:
		thread.start()
	# 阻塞线程
	for thread in threads:
		thread.join()





if __name__ == '__main__':

	window = tk.Tk()
	window.title('PortScan by L1nz')
	tool_gui = GUI(window)


	# pool = threadpool.ThreadPool(10)  # 建立线程池 开启10个线程
	#
	# requests = threadpool.makeRequests(PortScan.main(PortScan), )  # 提交10个任务到线程池
	#
	# for req in requests:  # 开始执行任务
	# 	pool.putRequest(req)  # 提交
	#
	# pool.wait()  # 等待完成

	# 测试
	# print(get_ip_list('10.101.144.94'))



