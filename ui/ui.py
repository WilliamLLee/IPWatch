from PyQt5.QtWidgets import QApplication,QLineEdit, QTableWidget,QWidget,QDialog,QFormLayout,QVBoxLayout,QHBoxLayout, QLabel, QRadioButton, QCheckBox, QTableWidgetItem,QPushButton
from PyQt5.QtGui import QIntValidator,QDoubleValidator,QFont, QIcon
from PyQt5.QtCore import QRect, QSize, Qt, right
import sys
import threading
import time
import socket

from utls import func


class PacketsAnalyzer(QDialog):
    def __init__(self, main_window, results):
        """
        Initialization function
        :param main_window: main windows object
        """
        super().__init__()
        self.setWindowTitle('Packets Analysis')
        self.main_window = main_window
        self.table = QVBoxLayout()
        self.results = results
        self.__init_ui()

    def __init_ui(self):
        # Set window size
        diglog_size = QSize(600,400)
        self.setFixedSize(diglog_size)
        # Set window icon
        self.setWindowIcon(QIcon('ui\icon\icon.ico'))
        
        # v Box Layout container
        left_container = QVBoxLayout()
        right_container = QVBoxLayout()
        # Set information display
        self.total_count, self.protocol_dic, self.service_dic = func.packet_count_func(self.results)
        self.tcp_udp_count = 0
        if 'TCP' in self.protocol_dic.keys():
                self.tcp_udp_count += self.protocol_dic['TCP']
        if 'UDP' in self.protocol_dic.keys():
                self.tcp_udp_count += self.protocol_dic['UDP']
        
        print(self.total_count, self.tcp_udp_count, self.protocol_dic, self.service_dic)
        
        left_container.addWidget(QLabel("Count By Session Protocol:"))
        left_container.addWidget(QLabel("Total Packet Count: {}".format(self.total_count)))
        right_container.addWidget(QLabel("Count By Application Service:"))
        right_container.addWidget(QLabel("Total TCP/UDP Count: {}".format(self.tcp_udp_count)))
        for protocol in func.protocol_list:
                if protocol in self.protocol_dic.keys():
                        left_container.addWidget(QLabel(protocol+":"+str(self.protocol_dic[protocol])+"(%.2f)"%(self.protocol_dic[protocol]/self.total_count)))
                else:
                        left_container.addWidget(QLabel(protocol+":"+"0"))
        for service in func.service_list:
                if self.tcp_udp_count!=0 and service in self.service_dic.keys():
                        right_container.addWidget(QLabel(service+":"+str(self.service_dic[service])+"(%.2f)"%(self.service_dic[service]/self.tcp_udp_count)))
                else:
                        right_container.addWidget(QLabel(service+":"+"0"))


        total_container = QHBoxLayout()
        total_container.addLayout(left_container)
        total_container.addLayout(right_container)

        self.table.addLayout(total_container)
        self.setLayout(self.table)
        self.adjustSize()
        self.show()


class MainFrameWindow(QWidget):
    '''
        design the main frame window
    '''
    def __init__(self,window_name,parent=None,debug_flag=False):
        super().__init__(parent)
        # the window title
        self.setWindowTitle(window_name)

        # the capture duration time limit, default is 10s
        self.duration_time = 10 
        # results of the capture
        self.results = []

        # basic componet
        self.time_limit = QLineEdit(self)
        self.src_ip = QLineEdit(self)
        self.dst_ip = QLineEdit(self)
        self.display_table = QTableWidget(self) 
        self.time_checkbox = QCheckBox(self)
        self.src_ip_checkbox = QCheckBox(self)
        self.dst_ip_checkbox = QCheckBox(self)
        self.state_info = QLabel(self)


        # get the resulotion of the screen
        self.screen_resolution = QApplication.desktop().screenGeometry()
        self.width = self.screen_resolution.width()
        self.height = self.screen_resolution.height()

        # get the size of the window
        self.window_width = self.width*0.5
        self.window_height = self.height*0.5
        # get the start position of the window
        self.window_start_x = self.width/2 - self.window_width/2
        self.window_start_y = self.height/2 - self.window_height/2
        # set the size  of the window
        self.window_rect = QRect(self.window_start_x,self.window_start_y,self.window_width,self.window_height)
        self.window_size = QSize(self.window_width,self.window_height)

        # set debug flag
        self.debug_flag = debug_flag

        # set the icon path
        self.icon_path = "ui\icon\icon.ico"

        # set the threading event
        self.thread_event = threading.Event()

        # init the ui of main frame window
        self.init_ui()

        # set the font
        self.font = QFont()
        self.font.setPointSize(12)
        self.font.setFamily("Consolas")

        if self.debug_flag:
            print("Debug mode is set now!")

    def init_ui(self):
        # set the size of the window
        self.setGeometry(self.window_rect)
        self.setFixedSize(self.window_size)

        # set icon of this window
        self.setWindowIcon(QIcon(self.icon_path))

        # set the layout
        total_layout = QVBoxLayout()
        top_layout = QVBoxLayout()
        top_layout_l1 = QHBoxLayout()
        top_layout_l2 = QHBoxLayout()
        middle_layout = QHBoxLayout()
        bottom_layout = QHBoxLayout()

        self.time_checkbox.setText("Time Limit(s):")
        self.src_ip_checkbox.setText("Source IP:")
        self.dst_ip_checkbox.setText("Destination IP:")

        self.time_checkbox.setChecked(True)
        self.src_ip_checkbox.setChecked(False)
        self.dst_ip_checkbox.setChecked(False)

        top_layout_l1.addWidget(self.time_checkbox)
        top_layout_l1.addWidget(self.time_limit)
        top_layout_l1.addWidget(self.src_ip_checkbox)
        top_layout_l1.addWidget(self.src_ip)
        top_layout_l1.addWidget(self.dst_ip_checkbox) 
        top_layout_l1.addWidget(self.dst_ip)

        start_button = QPushButton("Start Capture",self)
        start_button.clicked.connect(self.__start_capture)
        end_button = QPushButton("End Capture",self)
        end_button.clicked.connect(self.__end_capture)
        clear_button = QPushButton("Clear List",self)
        clear_button.clicked.connect(self.__clear_list)
        filter_button = QPushButton("Filter Result",self)
        filter_button.clicked.connect(self.__filter_display)
        analysis_button = QPushButton("Analysis Result",self)
        analysis_button.clicked.connect(self.__analysis_display)

        top_layout_l2.addWidget(start_button)
        top_layout_l2.addWidget(end_button)
        top_layout_l2.addWidget(clear_button)
        top_layout_l2.addWidget(filter_button)
        top_layout_l2.addWidget(analysis_button)

        top_layout.addLayout(top_layout_l1)
        top_layout.addLayout(top_layout_l2)

        self.display_table.setColumnCount(8)
        self.display_table.setHorizontalHeaderLabels(["Time",
                                                        "Source IP",
                                                        "Destination IP",
                                                        "Source Port",
                                                        "Destination Port",
                                                        "Session Protocol",
                                                        "Application Protocol",
                                                        "Version"])        
        self.display_table.setSortingEnabled (True)
        middle_layout.addWidget(self.display_table)

        state_info_hint = QLabel("Running Status:",self)
        bottom_layout.addWidget(state_info_hint)
        bottom_layout.addWidget(self.state_info)


        total_layout.addLayout(top_layout)
        total_layout.addLayout(middle_layout)
        total_layout.addLayout(bottom_layout)

        # set the widget
        self.setLayout(total_layout)

        # show the window
        self.show()

    def __start_capture(self):
        if self.__check_input_conditions():
            self.state_info.setText("Running, duration time is "+str(self.duration_time)+"s")
            self.thread_event.set()
            self.capture_task = func.MainIPCaptureWorker(self.device,self.ip_address,self.thread_event)
            self.controller = threading.Thread(
                    target = self.__time_control
            )
            self.capture_task.start()
            self.controller.start()
        else:
            self.state_info.setText("Error")
            return

    def __end_capture(self):
        if self.thread_event.is_set():
            self.thread_event.clear()
            for res in self.capture_task.get_result():
                self.results.append(res)
            self.__filter_display()
        else:
            self.state_info.setText("Error, the thread is not running.")
            return

    def __clear_list(self):
        self.results.clear()
        self.__set_display_table(self.results)
        self.state_info.setText("Packets is cleared!")
        pass

    def __get_src_ip(self):
        return self.src_ip.text()

    def __get_dst_ip(self):
        return self.dst_ip.text()

    def __get_time_limit(self):
        return self.time_limit.text()

    def __get_time_checkbox(self):
        return self.time_checkbox.isChecked()

    def __get_src_ip_checkbox(self):
        return self.src_ip_checkbox.isChecked() 

    def __get_dst_ip_checkbox(self): 
        return self.dst_ip_checkbox.isChecked()

    def __set_state_info(self,state_info):
        self.state_info.setText(state_info)

    def __filter_results(self):
        if self.__get_src_ip_checkbox():
            results= func.filter_by_src_ip(self.__get_src_ip(),self.results,)
        elif self.__get_dst_ip_checkbox():
            results = func.filter_by_dst_ip(self.__get_dst_ip(),self.results,)
        else:
            results = self.results
        return results

    def __filter_display(self):
        results = self.__filter_results()
        self.__display(results)

    def __analysis_display(self):
        analyzer =  PacketsAnalyzer(self,self.results)
        analyzer.show()
        analyzer.exec_()

    def __set_display_table(self,display_table):
        self.display_table.setRowCount(len(display_table))
        for i in range(len(display_table)):
            for j in range(8):
                self.display_table.setItem(i,j,QTableWidgetItem(display_table[i][j]))
    
    def __set_display_table_item(self,row,col,item):
        self.display_table.setItem(row,col,QTableWidgetItem(item))

    def __set_time_limit(self,time_limit):
        self.time_limit.setText(time_limit)

    def __set_src_ip(self,src_ip):
        self.src_ip.setText(src_ip)

    def __set_dst_ip(self,dst_ip):
        self.dst_ip.setText(dst_ip)

    def __time_control(self):
        time.sleep(self.duration_time)
        if self.thread_event.is_set():
            self.thread_event.clear()
            self.__set_state_info("Time is up now, the thread Finished.")
            for res in self.capture_task.get_result():
                self.results.append(res)
            self.results = self.__filter_results()
            self.__display(self.results)
        else:
            pass

    def __display(self,results):
        self.__set_state_info("Total packet number is "+str(len(results)))
        self.__set_display_table(results)
        self.show()
        pass

    def __check_input_conditions(self):
        if self.__get_time_checkbox():
            if self.__get_time_limit() == "":
                self.__set_state_info("Error, time limit is empty.")
                return False
            else:
                self.duration_time = int(self.__get_time_limit())
        if self.__get_src_ip_checkbox():
            if self.__get_src_ip() == "":
                self.__set_state_info("Error, source ip is empty.")
                return False
        if self.__get_dst_ip_checkbox():
            if self.__get_dst_ip() == "":
                self.__set_state_info("Error, destination ip is empty.")
                return False
        return True

    def get_results(self):
        return self.results

    def set_ip_capture_device(self):
        # get the device
        self.ip_address = func.get_ip_address(socket.gethostname())
        # get the row socket and bind it to the host address        
        # self.device = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.device = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.device.bind((self.ip_address,0))   # default bind to eth0 network adapter
        # Include IP headers
        self.device.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # set the socket to receive all the packages
        self.device.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def closeDevice(self):
        self.device.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        self.device.close()

if __name__ == "__main__":
    '''
        Test the function.
    '''
    app = QApplication(sys.argv)
    win = MainFrameWindow("IPWatch")
    win.set_ip_capture_device()
    sys.exit(app.exec_())
    