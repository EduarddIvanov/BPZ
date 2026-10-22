import sys
import base64

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPlainTextEdit, QComboBox,
    QLabel, QLineEdit, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QMessageBox, QFileDialog,
)
from PySide6.QtGui import QAction

from symmetric_cipher import SymmetricCipher, ALGORITHMS, MODES, CipherError

DEVELOPER = "Іванов Едуард Костянтинович"
GROUP = "ТВ-33"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Симетричне блокове шифрування (DES / TripleDES / AES)")
        self.resize(820, 600)
        self.current_path = None

        self._build_ui()
        self._build_actions()
        self._build_menu()
        self._build_toolbar()

    def _build_ui(self):
        self.algo_box = QComboBox()
        for name in ALGORITHMS:
            self.algo_box.addItem(name, name)
        self.algo_box.currentIndexChanged.connect(self._on_algo_changed)

        self.mode_box = QComboBox()
        for name in MODES:
            self.mode_box.addItem(name, name)
        self.mode_box.setCurrentText("CBC")
        self.mode_box.currentIndexChanged.connect(self._update_iv_state)

        self.key_edit = QLineEdit()
        self.iv_edit = QLineEdit()
        gen_key_btn = QPushButton("Згенерувати ключ")
        gen_iv_btn = QPushButton("Згенерувати IV")
        gen_key_btn.clicked.connect(self._gen_key)
        gen_iv_btn.clicked.connect(self._gen_iv)

        self.editor = QPlainTextEdit()

        top = QHBoxLayout()
        top.addWidget(QLabel("Алгоритм:"))
        top.addWidget(self.algo_box)
        top.addSpacing(15)
        top.addWidget(QLabel("Режим:"))
        top.addWidget(self.mode_box)
        top.addStretch()

        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Ключ (base64):"))
        key_row.addWidget(self.key_edit)
        key_row.addWidget(gen_key_btn)

        iv_row = QHBoxLayout()
        self._iv_label = QLabel("Вектор IV (base64):")
        iv_row.addWidget(self._iv_label)
        iv_row.addWidget(self.iv_edit)
        iv_row.addWidget(gen_iv_btn)

        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addLayout(key_row)
        layout.addLayout(iv_row)
        layout.addWidget(QLabel("Текст / шифрограма (base64):"))
        layout.addWidget(self.editor)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.statusBar().showMessage("Готово")

        self._gen_key()
        self._gen_iv()
        self._update_iv_state()

    def _build_actions(self):
        self.act_new = QAction("Створити", self, triggered=self.new_file)
        self.act_open = QAction("Відкрити", self, triggered=self.open_file)
        self.act_save = QAction("Зберегти", self, triggered=self.save_file)
        self.act_exit = QAction("Вихід", self, triggered=self.close)

        self.act_encrypt = QAction("Зашифрувати", self, triggered=self.encrypt)
        self.act_decrypt = QAction("Розшифрувати", self, triggered=self.decrypt)

        self.act_about = QAction("Про розробника", self, triggered=self.about)

    def _build_menu(self):
        menubar = self.menuBar()
        m_file = menubar.addMenu("Файл")
        m_file.addActions([self.act_new, self.act_open, self.act_save])
        m_file.addSeparator()
        m_file.addAction(self.act_exit)

        m_crypto = menubar.addMenu("Шифрування")
        m_crypto.addActions([self.act_encrypt, self.act_decrypt])

        m_help = menubar.addMenu("Довідка")
        m_help.addAction(self.act_about)

    def _build_toolbar(self):
        tb = self.addToolBar("Основне")
        tb.addActions([self.act_new, self.act_open, self.act_save])
        tb.addSeparator()
        tb.addActions([self.act_encrypt, self.act_decrypt])

    def _cipher(self):
        return SymmetricCipher(self.algo_box.currentData(), self.mode_box.currentData())

    def _on_algo_changed(self):
        self._gen_key()
        self._gen_iv()

    def _update_iv_state(self):
        needs_iv = MODES[self.mode_box.currentData()]["needs_iv"]
        self.iv_edit.setEnabled(needs_iv)
        self._iv_label.setEnabled(needs_iv)

    def _gen_key(self):
        key = self._cipher().generate_key()
        self.key_edit.setText(base64.b64encode(key).decode("ascii"))

    def _gen_iv(self):
        iv = self._cipher().generate_iv()
        self.iv_edit.setText(base64.b64encode(iv).decode("ascii"))

    def _read_key_iv(self):
        try:
            key = base64.b64decode(self.key_edit.text())
        except (ValueError, TypeError):
            raise CipherError("Ключ має бути у форматі base64")
        iv = None
        if MODES[self.mode_box.currentData()]["needs_iv"]:
            try:
                iv = base64.b64decode(self.iv_edit.text())
            except (ValueError, TypeError):
                raise CipherError("Вектор IV має бути у форматі base64")
        return key, iv

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
            key, iv = self._read_key_iv()
            result = self._cipher().encrypt_text(self.editor.toPlainText(), key, iv)
            self.editor.setPlainText(result)
            self.statusBar().showMessage("Зашифровано")
        except CipherError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def decrypt(self):
        try:
            key, iv = self._read_key_iv()
            result = self._cipher().decrypt_text(self.editor.toPlainText(), key, iv)
            self.editor.setPlainText(result)
            self.statusBar().showMessage("Розшифровано")
        except CipherError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def about(self):
        QMessageBox.about(
            self, "Про розробника",
            f"Криптосистема симетричного блокового шифрування\n\n"
            f"Розробник: {DEVELOPER}\n"
            f"Група: {GROUP}\n"
            f"Практична робота №5\n"
            f"Дисципліна: Безпека програмного забезпечення",
        )


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
