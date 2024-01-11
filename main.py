import sys
from PyQt6.QtWidgets import QApplication, QWidget, QStackedWidget, QVBoxLayout, QTableWidgetItem
from PyQt6 import QtWidgets
from login import LoginObject
from register import RegisterObject
from toDoManager import ToDoManagerObject
from toDoManagerUser import ToDoManagerUserObject
from pymongo import MongoClient
import hashlib
import secrets
import images_rc

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.client = MongoClient("mongodb://localhost:27017/")
        self.db = self.client["ToDoListDB"]
        self.users_collection = self.db["accountCredentials"]

        self.vlayout = QVBoxLayout(self)
        self.vlayout.setContentsMargins(0, 0, 0, 0)
        self.stackedWidget = QStackedWidget(self)
        self.stackedWidget.setContentsMargins(0, 0, 0, 0)

        self.loginWidget = QWidget()
        self.registerWidget = QWidget()
        self.toDoWidget = QWidget()
        self.toDoUserWidget = QWidget()

        self.stackedWidget.addWidget(self.loginWidget)
        self.stackedWidget.addWidget(self.registerWidget)
        self.stackedWidget.addWidget(self.toDoWidget)
        self.stackedWidget.addWidget(self.toDoUserWidget)

        self.vlayout.addWidget(self.stackedWidget)

        self.loggedUser = None
        self.loggedUsername = None

        self.loginPage()

        self.registerSpawned = False
        self.toDoPageUserSpawned = False
        self.toDoPageAdminSpawned = False

    def loginPage(self):
        self.login_object = LoginObject()
        self.login_object.setupUi(self.loginWidget)
        self.loginButton = self.login_object.loginButton
        self.createAccount = self.login_object.signUpLBL
        self.createAccount.mousePressEvent = self.showRegisterPage
        self.loginButton.clicked.connect(self.login)

    def registerPage(self):
        self.register_object = RegisterObject()
        self.register_object.setupUi(self.registerWidget)
        self.lbl = self.register_object.signInLBL
        self.lbl.mousePressEvent = self.showLoginPage
        self.registerButton = self.register_object.registerButton
        self.registerButton.clicked.connect(self.register)

    def toDoPageAdmin(self):
        self.toDoObject = ToDoManagerObject()
        self.toDoObject.setupUi(self.toDoWidget)
        self.toDoObject.nicknameLBL.setText(self.user_data["nickname"])
        self.addTaskBT = self.toDoObject.addTaskButton
        self.addTaskBT.clicked.connect(self.addTaskAdmin)
        self.assigneeList = self.toDoObject.assigneeListCB
        self.nicknames = []
        self.users = self.users_collection.find({}, {"nickname": 1, "_id": 0})
        self.assigneeList.clear()
        self.toDoObject.tableWidget.setColumnCount(3)
        self.toDoObject.tableWidget.removeRow(0)
        
        self.toDoObject.tableWidget.
        
        nicknames = []
        for user in self.users:
            nicknames.append(user["nickname"])
        self.assigneeList.addItems(nicknames)

        todo_list = self.user_data["toDoList"]

        for row, task_data in enumerate(reversed(todo_list)):
            self.toDoObject.tableWidget.insertRow(row)
            for col, data in enumerate(task_data):
                item = QtWidgets.QTableWidgetItem(str(data))
                self.toDoObject.tableWidget.setItem(row, col, item)
        self.toDoObject.tableWidget.resizeEvent = self.resizeColumnsRows
        self.toDoObject.searchLE.textChanged.connect(self.search)
        self.toDoObject.tableWidget.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Fixed)
    def search(self):
        search = self.toDoObject.searchLE.text().strip()
        self.toDoObject.tableWidget.setRowCount(0)
        todo_list = self.user_data["toDoList"]
        for row, task_data in enumerate(reversed(todo_list)):
            for col, data in enumerate(task_data):
                if search in data:
                    self.toDoObject.tableWidget.insertRow(row)
                    for col, data in enumerate(task_data):
                        item = QtWidgets.QTableWidgetItem(str(data))
                        self.toDoObject.tableWidget.setItem(row, col, item)
                    break
                elif search == "":
                    self.toDoObject.tableWidget.insertRow(row)
                    for col, data in enumerate(task_data):
                        item = QtWidgets.QTableWidgetItem(str(data))
                        self.toDoObject.tableWidget.setItem(row, col, item)
                    break
        
        
        
    
    def resizeColumnsRows(self, event):
        tableWidth = self.toDoObject.tableWidget.width()
        self.toDoObject.tableWidget.setColumnWidth(0, int(tableWidth/3))
        self.toDoObject.tableWidget.setColumnWidth(1, int(tableWidth/3))
        self.toDoObject.tableWidget.setColumnWidth(2, int(tableWidth/3))

        


    def toDoPageUser(self):
        self.toDoUserObject = ToDoManagerUserObject()
        self.toDoUserObject.setupUi(self.toDoUserWidget)
        self.toDoUserObject.nicknameLBL.setText(self.user_data["nickname"])
        self.users = self.users_collection.find({}, {"nickname": 1, "_id": 0})
        self.toDoUserObject.tableWidget.setColumnCount(3)
        todo_list = self.user_data["toDoList"]

        for row, task_data in enumerate(reversed(todo_list)):
            self.toDoUserObject.tableWidget.insertRow(row)
            for col, data in enumerate(task_data):
                item = QtWidgets.QTableWidgetItem(str(data))
                self.toDoUserObject.tableWidget.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()
        

    def showLoginPage(self, event):
        self.stackedWidget.setCurrentIndex(0)

    def showRegisterPage(self, event):
        if not self.registerSpawned:
            self.registerPage()
            self.registerSpawned = True
        self.stackedWidget.setCurrentIndex(1)

    def login(self):
        username_or_email = self.login_object.usernameLE.text().strip()
        password = self.login_object.passwordLE.text().strip()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.loggedUsername = username_or_email
        self.user_data = self.users_collection.find_one({"$or": [{"username": username_or_email}, {"email": username_or_email}]})

        self.login_object.loginWarningLBL.setStyleSheet("color: red;")

        if self.user_data is not None:
            stored_salt = self.user_data["salt"]
            input_hashed_password = hashlib.sha256((password + stored_salt).encode()).hexdigest()
            if self.user_data["type"] == "Admin":
                if input_hashed_password == self.user_data["password"]:
                    self.stackedWidget.setCurrentIndex(2)
                    self.login_object.loginWarningLBL.setText("")
                    if not self.toDoPageAdminSpawned:
                        self.toDoPageAdmin()
                        self.toDoPageAdminSpawned = True
                    return
            else:
                if input_hashed_password == self.user_data["password"]:
                    self.stackedWidget.setCurrentIndex(3)
                    self.login_object.loginWarningLBL.setText("")
                    if not self.toDoPageUserSpawned:
                        self.toDoPageUser()
                        self.toDoPageUserSpawned = True
                    return

        self.login_object.loginWarningLBL.setText("Your username or password is incorrect.")
        return


    def register(self):
        email = self.register_object.emailLE.text().strip()
        username = self.register_object.usernameLE.text().strip()
        password = self.register_object.passwordLE.text().strip()
        sPassword = self.register_object.passwordLE_2.text().strip()
        salt = secrets.token_hex(16)
        hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
        self.warning = self.register_object.registerWarningLBL

        def setWarningColor(color):
            self.warning.setStyleSheet(f"""
                color: {color};
            """)

        def setWarningText(text):
            self.warning.setText(text)

        setWarningColor("red")
        if self.users_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
            setWarningText("There's already an account with that username/email.")
        elif len(password) < 8:
            setWarningText("Your password must be at least 8 characters long.")
        elif password != sPassword:
            setWarningText("Your passwords do not match.")
        elif len(username) < 3:
            setWarningText("Your username is too short.")
        elif len(username) > 20:
            setWarningText("Your username is too long.")
        elif len(email) > 35:
            setWarningText("Your email is too long.")
        else:
            self.users_collection.insert_one({"type": "User", "username": username, "nickname": username, "email": email, "password": hashed_password, "salt": salt, "toDoList":[]})
            self.stackedWidget.setCurrentIndex(2)
            user_data = self.users_collection.find_one({"$or": [{"username": username}, {"email": email}]})

            self.users = self.users_collection.find({}, {"nickname": 1, "_id": 0})

            self.assigneeList.clear()
            nicknames = []
            for user in self.users:
                nicknames.append(user["nickname"])
            self.assigneeList.addItems(nicknames)
            
            self.loggedUser = user_data
            self.loggedUsername = username
            self.toDoObject.nicknameLBL.setText(self.loggedUser["nickname"])
            setWarningText("")
            setWarningColor("white")

            if not self.toDoPageUserSpawned:
                self.toDoPageUser()
                self.toDoPageUserSpawned = True
            return
            
    def addTaskAdmin(self):
        self.task = self.toDoObject.addTaskLE.text().strip()
        self.assignee = self.toDoObject.assigneeListCB.currentText()
        self.dueDate = self.toDoObject.dueDateLE.text()

        self.table = self.toDoObject.tableWidget

        self.table.insertRow(0)
        self.table.setItem(0, 0, QTableWidgetItem(self.task))
        self.table.setItem(0, 1, QTableWidgetItem(self.assignee))
        self.table.setItem(0, 2, QTableWidgetItem(self.dueDate))
        item = [self.task, self.assignee, self.dueDate]
        
        user_data = self.users_collection.find_one({"$or": [{"username": self.loggedUsername}, {"email": self.loggedUsername}]})
        user_data_assignee = self.users_collection.find_one({"nickname": self.assignee})
        
        if user_data:
            self.users_collection.update_one(
            {"_id": user_data["_id"]},
            {"$push": {"toDoList": item}}
        )
        
        if user_data_assignee:
            self.users_collection.update_one(
                {"_id": user_data_assignee["_id"]},
                {"$push": {"toDoList": item}}
            )
        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()
        

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())