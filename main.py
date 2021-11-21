import sys

from ui.ui import MainFrameWindow
from PyQt5.QtWidgets import QApplication


if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = MainFrameWindow("IPWatch")
    win.set_ip_capture_device()
    sys.exit(app.exec_())