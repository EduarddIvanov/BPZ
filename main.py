import sys

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPlainTextEdit, QComboBox, QLabel,
    QLineEdit, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QSplitter,
    QMessageBox, QFileDialog,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction

from rsa_signature import RSASigner, SignatureError, HASHES

DEVELOPER = "Іванов Едуард Костянтинович"
GROUP = "ТВ-33"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Електронний цифровий підпис на основі RSA")
        self.resize(900, 700)
        self.signer = RSASigner()
        self.current_path = None

        self._build_ui()
        self._build_actions()
        self._build_menu()
        self._build_toolbar()

    def _build_ui(self):
        self.hash_box = QComboBox()
        for name in HASHES:
            self.hash_box.addItem(name, name)
        self.hash_box.setCurrentText("SHA-256")
        self.hash_box.currentIndexChanged.connect(self._on_hash_changed)

        self.bits_box = QComboBox()
        for b in ("1024", "2048", "3072", "4096"):
            self.bits_box.addItem(b, int(b))
        self.bits_box.setCurrentText("2048")
        gen_btn = QPushButton("Згенерувати пару ключів")
        gen_btn.clicked.connect(self.generate_keys)

        top = QHBoxLayout()
        top.addWidget(QLabel("Геш:"))
        top.addWidget(self.hash_box)
        top.addSpacing(15)
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
        self.editor.setPlainText("Hello world!")

        self.sign_edit = QPlainTextEdit()
        self.sign_edit.setPlaceholderText("Цифровий підпис (base64)")
        self.sign_edit.setMaximumHeight(90)

        self.hash_view = QLineEdit()
        self.hash_view.setReadOnly(True)

        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(keys, 2)
        layout.addWidget(QLabel("Повідомлення:"))
        layout.addWidget(self.editor, 2)
        hash_row = QHBoxLayout()
        hash_row.addWidget(QLabel("Геш повідомлення:"))
        hash_row.addWidget(self.hash_view)
        layout.addLayout(hash_row)
        layout.addWidget(QLabel("Підпис (base64):"))
        layout.addWidget(self.sign_edit, 1)

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
        self.act_sign = QAction("Підписати", self, triggered=self.sign)
        self.act_verify = QAction("Перевірити підпис", self, triggered=self.verify)

        self.act_about = QAction("Про розробника", self, triggered=self.about)

    def _build_menu(self):
        menubar = self.menuBar()
        m_file = menubar.addMenu("Файл")
        m_file.addActions([self.act_new, self.act_open, self.act_save])
        m_file.addSeparator()
        m_file.addAction(self.act_exit)

        m_sign = menubar.addMenu("ЕЦП")
        m_sign.addAction(self.act_gen)
        m_sign.addSeparator()
        m_sign.addActions([self.act_sign, self.act_verify])

        m_help = menubar.addMenu("Довідка")
        m_help.addAction(self.act_about)

    def _build_toolbar(self):
        tb = self.addToolBar("Основне")
        tb.addActions([self.act_new, self.act_open, self.act_save])
        tb.addSeparator()
        tb.addActions([self.act_gen, self.act_sign, self.act_verify])

    def _on_hash_changed(self):
        self.signer = RSASigner(self.hash_box.currentData())
        self._update_hash_view()

    def _update_hash_view(self):
        try:
            self.hash_view.setText(self.signer.hash_hex(self.editor.toPlainText()))
        except SignatureError:
            self.hash_view.clear()

    def generate_keys(self):
        try:
            bits = self.bits_box.currentData()
            pub, priv = self.signer.generate_keys(bits)
            self.public_edit.setPlainText(pub)
            self.private_edit.setPlainText(priv)
            self.statusBar().showMessage(f"Згенеровано пару ключів {bits} біт")
        except SignatureError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def new_file(self):
        self.editor.clear()
        self.sign_edit.clear()
        self.hash_view.clear()
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

    def sign(self):
        try:
            self._update_hash_view()
            result = self.signer.sign(self.editor.toPlainText(), self.private_edit.toPlainText())
            self.sign_edit.setPlainText(result)
            self.statusBar().showMessage("Повідомлення підписано закритим ключем")
        except SignatureError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def verify(self):
        try:
            self._update_hash_view()
            ok = self.signer.verify(
                self.editor.toPlainText(),
                self.sign_edit.toPlainText(),
                self.public_edit.toPlainText(),
            )
            if ok:
                QMessageBox.information(self, "Перевірка ЕЦП", "Підпис дійсний: повідомлення не змінювалося.")
                self.statusBar().showMessage("Підпис дійсний")
            else:
                QMessageBox.warning(self, "Перевірка ЕЦП", "Підпис недійсний: повідомлення або підпис змінено.")
                self.statusBar().showMessage("Підпис недійсний")
        except SignatureError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def about(self):
        QMessageBox.about(
            self, "Про розробника",
            f"Електронний цифровий підпис на основі RSA\n\n"
            f"Розробник: {DEVELOPER}\n"
            f"Група: {GROUP}\n"
            f"Практична робота №8\n"
            f"Дисципліна: Безпека програмного забезпечення",
        )


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
