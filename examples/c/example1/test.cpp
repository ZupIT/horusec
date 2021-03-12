#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <sys/time.h>
#include <time.h>
#include <vector>
#include <map>

using namespace std;

int64_t getTime()
{
    struct timeval tval;
    gettimeofday(&tval, NULL);
    return tval.tv_sec * 1000000LL + tval.tv_usec;
}

int main(int argc, const char *argv[])
{
    //file<> fdoc("track_orig.xml");
    string xml_str, json_str;
    ifstream inf;
    ofstream outf;
    ostringstream oss;
    char BOM[4] = {(char)0xEF, (char)0xBB, (char)0xBF, '\0'}; /*BOM String*/
    int64_t start_time, end_time;

    inf.open("test.xml");
    outf.open("test.xml");
    oss.str("");
    oss << inf.rdbuf();
    xml_str = oss.str();
    inf.close();
    start_time = getTime();
    json_str = xml2json(xml_str.c_str());
    end_time = getTime();
    cout << "test: " << end_time - start_time << endl;
    outf << BOM << json_str;
    outf.close();

    inf.open("test.xml");
    outf.open("test.xml");
    oss.str("");
    oss << inf.rdbuf();
    xml_str = oss.str();
    inf.close();
    start_time = getTime();
    json_str = xml2json(xml_str.c_str());
    end_time = getTime();
    cout << "test: " << end_time - start_time << endl;
    outf << BOM << json_str;
    outf.close();

    inf.open("test.xml");
    outf.open("test.xml");
    oss.str("");
    oss << inf.rdbuf();
    xml_str = oss.str();
    inf.close();
    start_time = getTime();
    json_str = xml2json(xml_str.c_str());
    end_time = getTime();
    cout << "test: " << end_time - start_time << endl;
    outf << BOM << json_str;
    outf.close();

    return 0;
}
