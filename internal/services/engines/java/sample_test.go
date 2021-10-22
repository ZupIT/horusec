// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package java

const (
	SampleVulnerableJavaSQLInjection = `
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.sql.DataSource;

public class VulnerableCodeSQLInjection134 {

    public void printResults(DataSource ds, String field01) throws SQLException {
        try (
                var con = ds.getConnection();
                var pstmt = con.prepareStatement("select * from mytable where field01 = '" + field01 + "'");
                var rs = pstmt.executeQuery()) {
            while (rs.next()) {
                System.out.println(rs.getString(1));
            }
        }
    }
}
`

	SampleSafeJavaSQLInjection = `
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.sql.DataSource;

public class VulnerableCodeSQLInjection134 {

    public void printResults(DataSource ds, String field01) throws SQLException {
        try {
            var con = ds.getConnection();
            var pstmt = con.prepareStatement("select * from mytable where field01 = ? ");
            pstmt.setString(1,field01);
            var rs = pstmt.executeQuery();
            while (rs.next()) {
                System.out.println(rs.getString(1));
            }
        }
    }
}
`

	SampleVulnerableJavaXMLParsingVulnerableToXXE = `
class Foo {
	void fn(String input) {
		XMLReader reader = XMLReaderFactory.createXMLReader();
		reader.parse(input)
	}
}
	`

	SampleSafeJavaXMLParsingVulnerableToXXE = `
class Foo {
	void bar() {
		XMLReader reader = XMLReaderFactory.createXMLReader();
		reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		reader.setContentHandler(customHandler);
		
		reader.parse(new InputSource(inputStream));
	}
}
	`

	SampleVulnerableXMLParsingVulnerableToXXEWithDocumentBuilder = `
class Foo {
	void bar() {
		DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
		
		Document doc = db.parse(input);
	}
}
	`

	SampleSafeXMLParsingVulnerableToXXEWithDocumentBuilder = `
class Foo {
	void bar() {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		
		Document doc = db.parse(input);
	}
}
	`

	SampleVulnerableXMLParsingVulnerableToXXEWithSAXParserFactory = `
class Foo {
	void bar() {
		SAXParser parser = SAXParserFactory.newInstance().newSAXParser();
		
		parser.parse(inputStream, customHandler);
	}
}
	`

	SampleSafeXMLParsingVulnerableToXXEWithSAXParserFactory = `
class Foo {
	void bar() {
		SAXParserFactory spf = SAXParserFactory.newInstance();

		spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

		SAXParser parser = spf.newSAXParser();
	
		parser.parse(inputStream, customHandler);
	}
}
	`
)
