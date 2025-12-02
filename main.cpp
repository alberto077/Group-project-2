#include <iostream>
#include <string>
#include <unordered_set>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>


using namespace std;

unordered_set<string> loadWeakPasswords (const string& filename){
  unordered_set<string> weakPasswords;
  ifstream file(filename);
  string line;

  if (!file.is_open()) {
    cerr << "Error: could not open " << filename << endl;
    return weakPasswords;
}

  while(getline(file, line)){
    weakPasswords.insert(line);
  }

  return weakPasswords;

}

double analyzeLengthScore(const string& password) {
    int length = password.length();
    int printableASCIICharacters = 95;
    int MIN_ENTROPY = 40; //bits
    int MAX_ENTROPY = 80; // bits
    /* 
      Using the Claude Shannon's information theory to calculate entropy by 
      multiplying the length (L) by the logarithm base 2 of the 
      character range (R) to get it into bitwise operations. 
    */


    if (length < 8) {
        cout << "The NIST recommends a minimum password length of 8 characters for accounts where password is the only authentication factor, with a best practice of 15 characters or more." << endl;
        return 0.0;
    }
    else{
      double entropy = length * log2(printableASCIICharacters);

      double norm = (entropy - MIN_ENTROPY)/(MAX_ENTROPY - MIN_ENTROPY);
        
      norm = clamp(norm, 0.0, 1.0);  // close it in to [0, 1] for edge cases.

      // Future improvement: replace linear scaling with a sigmoid based function 

      return norm*10;
    }
}
double analyzeCommonPasswordScore(const string& password,const unordered_set<string>& weakPasswords){
  /*  
  Calculates a score based on how similar the password is 
  to the commonly used weak passwords file.
 
  Concept Logic:
  1. If the password is an exact match in the weak password list then return 0.
  2. If the password is a small modification of a known weak password
     (weak password plus 1–2 extra characters like “password1!” then 
     assign a low score (like 1–3 based on modification length).
  3. If the password just contains a known weak password as a substring,
     but has a lot additional randomness or length:
        - Assign a moderate score (3–6),
          scaled by how much randomness is outside the weak portion.
  4. If no similarity or weak pattern is detected:
        - Assign a high score (8–10)
          depending on total length or other things.
 
  Return format:
    value between 0 and 10.
  */
  return 0.0;
}


double analyzeCompositionScore(const string& password){
  /*
  Evaluates password strength based on character diversity.
  1. Count presence of character types:
       - Lowercase letters
       - Uppercase letters
       - Digits
       - Symbols / Special characters
 
  2. Score based on number of categories used:
       - 1 category only = weak (1–3)
       - 2 categories = moderate (4–6)
       - 3 categories = strong (7–9)
       - 4 categories = very strong (9–10)
 
  Return format:
    value between 0 and 10 
 */
  bool hasLower = false;
  bool hasUpper = false;
  bool hasDigit = false;
  bool hasSpecial = false;

  for (char c : password) {
    if (islower(c)) hasLower = true;
    else if (isupper(c)) hasUpper = true;
    else if (isdigit(c)) hasDigit = true;
    else hasSpecial = true;
  }

  cout << "\nImprovements: " << endl;
  if (!hasLower)
        cout << "- Add lowercase letters (a–z)\n";
    if (!hasUpper)
        cout << "- Add uppercase letters (A–Z)\n";
    if (!hasDigit)
        cout << "- Add digits (0–9)\n";
    if (!hasSpecial)
        cout << "- Add special characters (!@#$%^&*, etc.)\n";

  int categories = hasLower + hasUpper + hasDigit + hasSpecial;

  if (categories == 1) return 2; 
  if (categories == 2) return 5;
  if (categories == 3) return 8;
  if (categories == 4) return 10;

  return 0.0;
}

int main() {
  string password;

  cout << "Enter a password to test" << endl;
  cin >> password;
  
  double lengthScore = analyzeLengthScore(password);
  cout << lengthScore << endl;
  double compositionScore = analyzeCompositionScore(password);
  cout << "Character Diversity Score: " << compositionScore << endl;  
  return 0;
}
