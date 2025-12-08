#include <iostream>
#include <string>
#include <unordered_set>
#include <fstream>
#include <vector>
#include <cmath>
#include <cctype>
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
        cout << "\n- The NIST recommends a minimum password length of 8 characters for accounts where password is the only authentication factor, with a best practice of 15 characters or more." << endl;
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
    
  int length = password.length();

    // 1. Exact Match
    if (weakPasswords.find(password) != weakPasswords.end()) {
        cout << "\n- This password is not secure, found in list of common passwords.Change it to something random. " << endl;
        return 0.0;
    }

    for (const string& weak : weakPasswords) {

      if (weak.length() < 4) continue;
        // 2. Weak password + 1–2 extra characters

        if (password.find(weak) == 0) {
            int extra = length - weak.length();

            if (extra == 1) {
                cout << "\nPassword is very weak (simple modification)." << endl;
                cout << "Suggestion: Avoid adding just one character. Use a longer, unpredictable password.\n";
                return 1.0;
            }

            if (extra == 2) {
                cout << "\nPassword is weak (minor modification)." << endl;
                cout << "Suggestion: Add more randomness and mix uppercase, numbers, and symbols.\n";
                return 3.0;
            }
        }

        // 3. Weak password appears inside with more randomness
        if (password.find(weak) != string::npos) {
            int extra = length - weak.length();

            if (extra <= 3) {
                cout << "\nPassword is weak (common word found)." << endl;
                cout << "Suggestion: Remove the common word entirely.\n";
                return 3.0;
            }

            if (extra <= 5) {
                
                cout << "\nPassword is moderate but still risky." << endl;
                cout << "Suggestion: Increase length and add more unpredictability.\n";
                return 5.0;
            }

            
            cout << "\nPassword is moderate strength." << endl;
            cout << "Suggestion: Still contains weak patterns. Consider a completely random password.\n";
            return 6.0;
        }
    }


    if (length >= 12) {
        
        cout << "\nPassword is very strong." << endl;
        cout << "Great job! Keep using long, complex passwords.\n";
        return 10.0;
    }

    if (length >= 10) {
        
        cout << "\nPassword is strong." << endl;
        cout << "Suggestion: Adding one more symbol could make it even stronger.\n";
        return 9.0;
    }

    if (length >= 8) {
        
        cout << "\nPassword is fairly strong." << endl;
        cout << "Suggestion: Consider increasing length or adding more symbols.\n";
        return 8.0;
    }
     // 4. No similarity or weak pattern is detected
    cout << "\nPassword is decent but could be stronger." << endl;
    cout << "Suggestion: Increase length and include symbols and numbers.\n";
    return 7.0;
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
    if (islower((unsigned char)c)) hasLower = true;
    else if (isupper((unsigned char)c)) hasUpper = true;
    else if (isdigit((unsigned char)c)) hasDigit = true;
    else hasSpecial = true;
  }
  
  int categories = hasLower + hasUpper + hasDigit + hasSpecial;

  if (categories == 1) return 2; 
  if (categories == 2) return 5;
  if (categories == 3) return 8;
  if (categories == 4) return 10;

  return 0.0;
}

void generateFeedback(const string& password, vector<string>& feedback) {
// Function used to give users feedback on their passwords.

    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (char c : password) {   
        if (islower((unsigned char)c)) hasLower = true;
        else if (isupper((unsigned char)c)) hasUpper = true;
        else if (isdigit((unsigned char)c)) hasDigit = true;
        else hasSpecial = true;
    }

    if (!hasLower)
        feedback.push_back("Add lowercase letters (a–z).");

    if (!hasUpper)
        feedback.push_back("Add uppercase letters (A–Z).");

    if (!hasDigit)
        feedback.push_back("Add digits (0–9).");

    if (!hasSpecial)
        feedback.push_back("Add special characters (!@#$%^&*, etc.).");
}


int main() {
  string password;
  double total;
  vector<string> feedback;
  unordered_set<string> weakPasswords = loadWeakPasswords("passwords.txt");


  cout << "***Password Strength Evaluation Program***" << endl;
  cout << "By: Harpreet Singh, Alberto Santana, and Jordanna Jervis" << endl;
  cout << "\nEnter a password to test:" << endl;
  cin >> password;

  double lengthScore = analyzeLengthScore(password);
  cout << "\nScore Length: " << lengthScore << endl;

  double commonScore = analyzeCommonPasswordScore(password, weakPasswords);
  cout << "\nCommon Password Score: " << commonScore << endl;

  double compositionScore = analyzeCompositionScore(password);
  cout << "\nCharacter Diversity Score: " << compositionScore << endl;
  generateFeedback(password, feedback);
  if (!feedback.empty()) {
    cout << "\nSuggestions:\n";
    for (const string& msg : feedback) {
        cout << "- " << msg << endl;
    }
} else {
    cout << "\nGreat job! No suggestions needed.\n";
}

total = lengthScore + commonScore + compositionScore;

cout << "\nTotal Score: " << total << "/30" << endl;

  return 0;
}
