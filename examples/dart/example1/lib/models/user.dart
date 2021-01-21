class User {
  int _id;
  String _username;
  String _password;

  User(this._username, this._password);

  User.fromMap(dynamic obj) {
    this._id = obj['id'];
    this._username = obj['username'];
    this._password = obj['password'];
  }

  String get username => _username;
  String get password => _password;
  int get id => _id;

  Map<String, dynamic> toMap() {
    var map = new Map<String, dynamic>();
    map["id"] = _id;
    map["username"] = _username;
    map["password"] = _password;
    return map;
  }
}