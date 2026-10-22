import sys

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPlainTextEdit, QComboBox, QSpinBox,
    QLabel, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QMessageBox, QFileDialog, QTableWidget, QTableWidgetItem,
)
from PySide6.QtGui import QAction
from PySide6.QtCore import Qt

from book_cipher import BookCipher, PoemKey, CipherError, DEFAULT_POEM
from word_book_cipher import WordBookCipher, DEFAULT_BOOK

DEVELOPER = "Іванов Едуард Костянтинович"
GROUP = "ТВ-33"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Книжковий шифр — криптосистема")
        self.resize(860, 640)
        self.current_path = None

        self._build_ui()
        self._build_actions()
        self._build_menu()
        self._build_toolbar()
        self._refresh_grid()

    def _build_ui(self):
        self.mode_box = QComboBox()
        self.mode_box.addItem("Віршований (координати)", "poem")
        self.mode_box.addItem("Пословний (номери слів)", "word")
        self.mode_box.currentIndexChanged.connect(self._on_mode_changed)

        self.rows_spin = self._make_spin(10)
        self.cols_spin = self._make_spin(10)
        self.rows_spin.valueChanged.connect(self._refresh_grid)
        self.cols_spin.valueChanged.connect(self._refresh_grid)

        self.key_edit = QPlainTextEdit(DEFAULT_POEM)
        self.key_edit.setMaximumHeight(130)
        self.key_edit.textChanged.connect(self._refresh_grid)

        self.grid_view = QTableWidget()
        self.grid_view.setEditTriggers(QTableWidget.NoEditTriggers)
        self.grid_view.setMaximumHeight(240)

        self.editor = QPlainTextEdit()

        top = QHBoxLayout()
        top.addWidget(QLabel("Різновид:"))
        top.addWidget(self.mode_box)
        top.addSpacing(15)
        self._rows_label = QLabel("Рядків:")
        self._cols_label = QLabel("Стовпців:")
        top.addWidget(self._rows_label)
        top.addWidget(self.rows_spin)
        top.addWidget(self._cols_label)
        top.addWidget(self.cols_spin)
        top.addStretch()

        self._key_label = QLabel("Ключ (вірш):")

        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(self._key_label)
        layout.addWidget(self.key_edit)
        layout.addWidget(self.grid_view)
        layout.addWidget(QLabel("Текст / шифрограма:"))
        layout.addWidget(self.editor)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.statusBar().showMessage("Готово")

    def _make_spin(self, value):
        spin = QSpinBox()
        spin.setRange(1, 30)
        spin.setValue(value)
        return spin

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

    def _mode(self):
        return self.mode_box.currentData()

    def _on_mode_changed(self):
        poem = self._mode() == "poem"
        for w in (self.rows_spin, self.cols_spin, self._rows_label,
                  self._cols_label, self.grid_view):
            w.setVisible(poem)
        self._key_label.setText("Ключ (вірш):" if poem else "Ключ (текст-книга):")
        self.key_edit.setPlainText(DEFAULT_POEM if poem else DEFAULT_BOOK)

    def _build_poem_key(self):
        return PoemKey(self.key_edit.toPlainText(),
                       self.rows_spin.value(), self.cols_spin.value())

    def _refresh_grid(self):
        if self._mode() != "poem":
            return
        try:
            key = self._build_poem_key()
        except CipherError:
            self.grid_view.clear()
            return
        self.grid_view.setRowCount(len(key.grid))
        self.grid_view.setColumnCount(self.cols_spin.value())
        for r, row in enumerate(key.grid):
            for c in range(self.cols_spin.value()):
                ch = row[c].upper() if c < len(row) else ""
                item = QTableWidgetItem(ch)
                item.setTextAlignment(Qt.AlignCenter)
                self.grid_view.setItem(r, c, item)
        self.grid_view.resizeColumnsToContents()

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
        self._run(encrypt=True)

    def decrypt(self):
        self._run(encrypt=False)

    def _run(self, encrypt):
        text = self.editor.toPlainText()
        try:
            if self._mode() == "poem":
                cipher = BookCipher()
                key = self._build_poem_key()
                result = cipher.encrypt(text, key) if encrypt else cipher.decrypt(text, key)
            else:
                cipher = WordBookCipher(self.key_edit.toPlainText())
                result = cipher.encrypt(text) if encrypt else cipher.decrypt(text)
            self.editor.setPlainText(result)
            self.statusBar().showMessage("Зашифровано" if encrypt else "Розшифровано")
        except CipherError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def about(self):
        QMessageBox.about(
            self, "Про розробника",
            f"Криптосистема на основі книжкового шифру\n\n"
            f"Розробник: {DEVELOPER}\n"
            f"Група: {GROUP}\n"
            f"Практична робота №3\n"
            f"Дисципліна: Безпека програмного забезпечення",
        )


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
