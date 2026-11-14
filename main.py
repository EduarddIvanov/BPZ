import sys

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPlainTextEdit, QComboBox, QLabel,
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QSplitter,
    QMessageBox, QFileDialog,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction

from rsa_cipher import RSACipher, RSAError

DEVELOPER = "Іванов Едуард Костянтинович"
GROUP = "ТВ-33"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Асиметричне шифрування RSA")
        self.resize(900, 640)
        self.cipher = RSACipher()
        self.current_path = None

        self._build_ui()
        self._build_actions()
        self._build_menu()
        self._build_toolbar()

    def _build_ui(self):
        self.bits_box = QComboBox()
        for b in ("1024", "2048", "3072", "4096"):
            self.bits_box.addItem(b, int(b))
        self.bits_box.setCurrentText("2048")
        gen_btn = QPushButton("Згенерувати пару ключів")
        gen_btn.clicked.connect(self.generate_keys)

        top = QHBoxLayout()
        top.addWidget(QLabel("Довжина ключа (біт):"))
        top.addWidget(self.bits_box)
        top.addWidget(gen_btn)
        top.addStretch()

        self.public_edit = QPlainTextEdit()
        self.public_edit.setPlaceholderText("Відкритий ключ (PEM)")
        self.private_edit = QPlainTextEdit()
        self.private_edit.setPlaceholderText("Закритий ключ (PEM)")

        keys = QSplitter(Qt.Horizontal)
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(QLabel("Відкритий ключ:"))
        lv.addWidget(self.public_edit)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(QLabel("Закритий ключ:"))
        rv.addWidget(self.private_edit)
        keys.addWidget(left)
        keys.addWidget(right)

        self.editor = QPlainTextEdit()

        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(keys, 1)
        layout.addWidget(QLabel("Текст / шифрограма (base64):"))
        layout.addWidget(self.editor, 1)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.statusBar().showMessage("Готово")

    def _build_actions(self):
        self.act_new = QAction("Створити", self, triggered=self.new_file)
        self.act_open = QAction("Відкрити", self, triggered=self.open_file)
        self.act_save = QAction("Зберегти", self, triggered=self.save_file)
        self.act_exit = QAction("Вихід", self, triggered=self.close)

        self.act_gen = QAction("Сформувати ключі", self, triggered=self.generate_keys)
        self.act_encrypt = QAction("Зашифрувати", self, triggered=self.encrypt)
        self.act_decrypt = QAction("Розшифрувати", self, triggered=self.decrypt)

        self.act_about = QAction("Про розробника", self, triggered=self.about)

    def _build_menu(self):
        menubar = self.menuBar()
        m_file = menubar.addMenu("Файл")
        m_file.addActions([self.act_new, self.act_open, self.act_save])
        m_file.addSeparator()
        m_file.addAction(self.act_exit)

        m_crypto = menubar.addMenu("RSA")
        m_crypto.addAction(self.act_gen)
        m_crypto.addSeparator()
        m_crypto.addActions([self.act_encrypt, self.act_decrypt])

        m_help = menubar.addMenu("Довідка")
        m_help.addAction(self.act_about)

    def _build_toolbar(self):
        tb = self.addToolBar("Основне")
        tb.addActions([self.act_new, self.act_open, self.act_save])
        tb.addSeparator()
        tb.addActions([self.act_gen, self.act_encrypt, self.act_decrypt])

    def generate_keys(self):
        try:
            bits = self.bits_box.currentData()
            pub, priv = self.cipher.generate_keys(bits)
            self.public_edit.setPlainText(pub)
            self.private_edit.setPlainText(priv)
            self.statusBar().showMessage(f"Згенеровано пару ключів {bits} біт")
        except RSAError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def new_file(self):
        self.editor.clear()
        self.current_path = None
        self.statusBar().showMessage("Новий документ")

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Відкрити файл", "", "Текстові файли (*.txt);;Усі файли (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.editor.setPlainText(f.read())
            self.current_path = path
            self.statusBar().showMessage(f"Відкрито: {path}")
        except (OSError, UnicodeDecodeError) as e:
            QMessageBox.warning(self, "Помилка", f"Не вдалося відкрити файл:\n{e}")

    def save_file(self):
        path = self.current_path
        if not path:
            path, _ = QFileDialog.getSaveFileName(self, "Зберегти файл", "", "Текстові файли (*.txt);;Усі файли (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.editor.toPlainText())
            self.current_path = path
            self.statusBar().showMessage(f"Збережено: {path}")
        except OSError as e:
            QMessageBox.warning(self, "Помилка", f"Не вдалося зберегти файл:\n{e}")

    def encrypt(self):
        try:
            result = self.cipher.encrypt(self.editor.toPlainText(), self.public_edit.toPlainText())
            self.editor.setPlainText(result)
            self.statusBar().showMessage("Зашифровано відкритим ключем")
        except RSAError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def decrypt(self):
        try:
            result = self.cipher.decrypt(self.editor.toPlainText(), self.private_edit.toPlainText())
            self.editor.setPlainText(result)
            self.statusBar().showMessage("Розшифровано закритим ключем")
        except RSAError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def about(self):
        QMessageBox.about(
            self, "Про розробника",
            f"Асиметричне шифрування RSA\n\n"
            f"Розробник: {DEVELOPER}\n"
            f"Група: {GROUP}\n"
            f"Практична робота №7\n"
            f"Дисципліна: Безпека програмного забезпечення",
        )


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
