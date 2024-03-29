#include <bits/stdc++.h>
#include <sys/stat.h>
using namespace std;

#define REG0 "regs/reg0"
#define REG1 "regs/reg1"
#define REG2 "regs/reg2"
#define REG3 "regs/reg3"
#define REG4 "regs/reg4"
#define REG5 "regs/reg5"
#define REG6 "regs/reg6"
#define REG7 "regs/reg7"
#define REG8 "regs/reg8"
#define REG9 "regs/reg9"
#define REGA "regs/rega"
#define REGB "regs/regb"
#define REGC "regs/regc"
#define REGD "regs/regd"
#define REGE "regs/rege"
#define REGF "regs/regf"

const string regs[] = {REG0, REG1, REG2, REG3, REG4, REG5, REG6, REG7, REG8, REG9, REGA, REGB, REGC, REGD, REGE, REGF};

void interpret(ifstream &file_in){

    char c;
    bool finish = false;
    
    while(((file_in.get(c), file_in.eof()) == false) && (!finish)){
        string s1, s2;
        long long n1, n2;
        switch (c){
            case 40: // unconditional jmp
                ifstream(REGA) >> n1;
                file_in.seekg(n1, file_in.cur);
                break;
            case 41: // je
                ifstream(REGA) >> n1;
                ifstream(REGB) >> s1;
                ifstream(REGC) >> s2;
                if(s1 == s2){
                    file_in.seekg(n1, file_in.cur);
                }
                break;
            case 42: // jne
                ifstream(REGA) >> n1;
                ifstream(REGB) >> s1;
                ifstream(REGC) >> s2;
                if(s1 != s2){
                    file_in.seekg(n1, ios_base::cur);
                }
                break;
            case 43: // jb
                ifstream(REGB) >> n1;
                ifstream(REGC) >> n2;
                if(n1 < n2){
                    ifstream(REGA) >> n1;
                    file_in.seekg(n1, file_in.cur);
                }
                break;
            case 44: // init_s REG0
                remove(REG0);
                ofstream(REG0) << "";
                break;
            case 45: // init_s REG1
                remove(REG1);
                ofstream(REG1) << "";
                break;
            case 46: // init_s REG2
                remove(REG2);
                ofstream(REG2) << "";
                break;
            case 47: // init_s REG3
                remove(REG3);
                ofstream(REG3) << "";
                break;
            case 48: // init_s REG4
                remove(REG4);
                ofstream(REG4) << "";
                break;
            case 49: // init_s REG5
                remove(REG5);
                ofstream(REG5) << "";
                break;
            case 50: // init_s REG6
                remove(REG6);
                ofstream(REG6) << "";
                break;
            case 51: // init_s REG7
                remove(REG7);
                ofstream(REG7) << "";
                break;
            case 52: // init_s REG8
                remove(REG8);
                ofstream(REG8) << "";
                break;
            case 53: // init_s REG9
                remove(REG9);
                ofstream(REG9) << "";
                break;
            case 54: // init_s REGA
                remove(REGA);
                ofstream(REGA) << "";
                break;
            case 55: // init_s REGB
                remove(REGB);
                ofstream(REGB) << "";
                break;
            case 56: // init_s REGC
                remove(REGC);
                ofstream(REGC) << "";
                break;
            case 57: // init_s REGD
                remove(REGD);
                ofstream(REGD) << "";
                break;
            case 58: // init_s REGE
                remove(REGE);
                ofstream(REGE) << "";
                break;
            case 59: // init_s REGF
                remove(REGF);
                ofstream(REGF) << "";
                break;
            case 61: // ord
                file_in.get(c);
                ifstream(regs[c]) >> s1;
                file_in.get(c);
                remove(regs[c].c_str());
                ofstream(regs[c]) << int(char(s1[s1.size()-1]));
                break;
            case 62: // chr
                file_in.get(c);
                ifstream(regs[c]) >> n1;
                file_in.get(c);
                remove(regs[c].c_str());
                ofstream(regs[c]) << char(n1 & 0xff);
                break;
            case 63: // concat
                file_in.get(c);
                ifstream(regs[c]) >> s1;
                file_in.get(c);
                ifstream(regs[c]) >> s2;
                s1 += s2;
                file_in.get(c);
                remove(regs[c].c_str());
                ofstream(regs[c]) << s1;
                break;
            case 64: // init_n REG0
                remove(REG0);
                ofstream(REG0).put('0');
                break;
            case 65: // init_n REG1
                remove(REG1);
                ofstream(REG1).put('0');
                break;
            case 66: // init_n REG2
                remove(REG2);
                ofstream(REG2).put('0');
                break;
            case 67: // init_n REG3
                remove(REG3);
                ofstream(REG3).put('0');
                break;
            case 68: // init_n REG4
                remove(REG4);
                ofstream(REG4).put('0');
                break;
            case 69: // init_n REG5
                remove(REG5);
                ofstream(REG5).put('0');
                break;
            case 70: // init_n REG6
                remove(REG6);
                ofstream(REG6).put('0');
                break;
            case 71: // init_n REG7
                remove(REG7);
                ofstream(REG7).put('0');
                break;
            case 72: // init_n REG8
                remove(REG8);
                ofstream(REG8).put('0');
                break;
            case 73: // init_n REG9
                remove(REG9);
                ofstream(REG9).put('0');
                break;
            case 74: // init_n REGA
                remove(REGA);
                ofstream(REGA).put('0');
                break;
            case 75: // init_n REGB
                remove(REGB);
                ofstream(REGB).put('0');
                break;
            case 76: // init_n REGC
                remove(REGC);
                ofstream(REGC).put('0');
                break;
            case 77: // init_n REGD
                remove(REGD);
                ofstream(REGD).put('0');
                break;
            case 78: // init_n REGE
                remove(REGE);
                ofstream(REGE).put('0');
                break;
            case 79: // init_n REGF
                remove(REGF);
                ofstream(REGF).put('0');
                break;
            case 80: // "log" REG0
                file_in.get(c);
                getline(ifstream(regs[c]), s1);
                remove(REG0);
                ofstream(REG0) << s1.size();
                break;
            case 81: // add
                file_in.get(c);
                ifstream(regs[c]) >> n1;
                file_in.get(c);
                ifstream(regs[c]) >> n2;
                n1 += n2;
                file_in.get(c);
                remove(regs[c].c_str());
                ofstream(regs[c]) << n1;
                break;
            case 82: // base10 lshift plus 1
                file_in.get(c);
                ofstream(regs[c], ios_base::app) << "1";
                break;
            case 83: // base10 rshift
                file_in.get(c);
                ifstream(regs[c]) >> s1;
                if(s1.size()){
                    s1.pop_back();
                    remove(regs[c].c_str());
                    ofstream(regs[c], ios_base::app) << s1;
                }
                break;
            case 84: // opposite
                file_in.get(c);
                ifstream(regs[c]) >> s1;
                remove(regs[c].c_str());
                if(s1[0] == '-'){
                    s1.erase(0, 1);
                    ofstream(regs[c]) << s1;
                }
                else{
                    ofstream(regs[c]) << "-" << s1;
                }
                break;
            case 85: // print
                ifstream(REGF) >> s1;
                cout << s1 << endl;
                break;
            case 86: // read REG0
                ifstream(REG0) >> s1;
                if(ifstream(s1.c_str()).fail()){
                    s1 = "-1";
                }
                else{
                    ifstream(s1.c_str()) >> s1;
                }
                ofstream(REG0) << s1;
                break;
            case 87: // exit
                finish = true;
                break;
            default:
                cout << endl << "Unknown instruction " << int(c) << " at " << file_in.tellg() << endl;
                return;
        }
    }
}

int main(int argc, char** argv){

    if(argc != 2){
        cout << "Usage: " << argv[0] << " <bytecode>" << endl;
        exit(EXIT_FAILURE);
    }

    ifstream file_in(argv[1], ios_base::in | ios_base::binary);

    if(file_in.fail()){
        cout << "File " << argv[1] << " does not exist" << endl;
        exit(EXIT_FAILURE);
    }

    mkdir("regs", S_IRWXU);
    
    interpret(file_in);

    for(auto reg: regs){
        remove(reg.c_str());
    }

    system("rmdir regs");

    return 0;
}