import 'package:flutter/material.dart';
import 'package:simple_form_crud/screens/home_pages.dart';

void main() => runApp(new MyApp());

final routes = {
  '/home': (BuildContext context) => new HomePage(),
  '/': (BuildContext context) => new HomePage(),
};

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return new MaterialApp(
      title: 'Sqflite App',
      theme: new ThemeData(primarySwatch: Colors.teal),
      routes: routes,
    );
  }
}