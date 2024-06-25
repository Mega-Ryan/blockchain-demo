#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "lattice/backend.h"
#include "lattice/trapdoor.h"
#include "math/backend.h"
#include "math/distrgen.h"
#include "math/matrix.h"
#include "math/nbtheory.h"
#include "napi.h"
#include "nlohmann/json.hpp"
#include "palisade.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;

const uint32_t k_256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void modifyJsonValue(std::string filename)
{
  // Load the JSON file
  std::ifstream input_file(filename);
  nlohmann::ordered_json j;
  input_file >> j;

  // Check and modify the value of key "f"
  try
  {
    nlohmann::ordered_json &f = j["value0"]["d"][0][0]["f"];
    // Check if the key exists and if the value is 1, then modify it
    if (f.is_number() && f.get<int>() == 1)
    {
      f = 0; // Change the value to 0
      std::cout << "Value of 'f' changed to 0." << std::endl;
    }
  }
  catch (const nlohmann::ordered_json::exception &e)
  {
    std::cerr << "Error accessing key 'f': " << e.what() << std::endl;
  }

  // Save the modified JSON back to the file
  std::ofstream output_file(filename);
  output_file << j.dump(4); // dump with an indent of 4 spaces
}

class ChameleonHash
{
private:
#define RIGHT_ROT(x, n)          \
  ((x >> (n % (sizeof(x) * 8)) | \
    (x << ((sizeof(x) * 8) - (n % (sizeof(x) * 8))))))

  static void SHA256(string &message, vector<int64_t> &digest)
  {
    uint32_t h_256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    uint64_t m_len = message.size() * 8;
    uint16_t pad_len = 1;
    while ((m_len + pad_len) % 512 != 448)
    {
      pad_len++;
    }
    message.push_back(0);
    for (int a = 0; a < (pad_len) / 8 - 1; a++)
    {
      message.push_back(0);
    }
    message.push_back((uint8_t)((m_len & 0xff00000000000000) >> 56));
    message.push_back((uint8_t)((m_len & 0x00ff000000000000) >> 48));
    message.push_back((uint8_t)((m_len & 0x0000ff0000000000) >> 40));
    message.push_back((uint8_t)((m_len & 0x000000ff00000000) >> 32));
    message.push_back((uint8_t)((m_len & 0x00000000ff000000) >> 24));
    message.push_back((uint8_t)((m_len & 0x0000000000ff0000) >> 16));
    message.push_back((uint8_t)((m_len & 0x000000000000ff00) >> 8));
    message.push_back((uint8_t)(m_len & 0x00000000000000ff));

    for (size_t n = 0; n < (message.size() * 8) / 512; n++)
    {
      uint32_t w[64];
      short counter = 0;
      for (size_t m = 64 * n; m < (64 * (n + 1)); m += 4)
      {
        w[counter] = ((uint32_t)message.at(m) << 24) ^
                     ((uint32_t)message.at(m + 1) << 16) ^
                     ((uint32_t)message.at(m + 2) << 8) ^
                     ((uint32_t)message.at(m + 3));
        counter++;
      }
      for (int i = 16; i < 64; i++)
      {
        uint32_t s0 = ((uint32_t)RIGHT_ROT(w[i - 15], 7)) ^
                      ((uint32_t)(RIGHT_ROT(w[i - 15], 18))) ^
                      ((uint32_t)(w[i - 15] >> 3));
        uint32_t s1 = ((uint32_t)RIGHT_ROT(w[i - 2], 17)) ^
                      ((uint32_t)RIGHT_ROT(w[i - 2], 19)) ^
                      ((uint32_t)(w[i - 2] >> 10));
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
      }

      uint32_t a = h_256[0];
      uint32_t b = h_256[1];
      uint32_t c = h_256[2];
      uint32_t d = h_256[3];
      uint32_t e = h_256[4];
      uint32_t f = h_256[5];
      uint32_t g = h_256[6];
      uint32_t h = h_256[7];

      for (int i = 0; i < 64; i++)
      {
        uint32_t S1 = ((uint32_t)RIGHT_ROT(e, 6)) ^
                      ((uint32_t)RIGHT_ROT(e, 11)) ^
                      ((uint32_t)RIGHT_ROT(e, 25));
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + k_256[i] + w[i];
        uint32_t S0 = ((uint32_t)RIGHT_ROT(a, 2)) ^
                      ((uint32_t)RIGHT_ROT(a, 13)) ^
                      ((uint32_t)RIGHT_ROT(a, 22));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
      }

      h_256[0] += a;
      h_256[1] += b;
      h_256[2] += c;
      h_256[3] += d;
      h_256[4] += e;
      h_256[5] += f;
      h_256[6] += g;
      h_256[7] += h;
    }

    for (int i = 0; i < 8; i++)
    {
      digest.push_back(h_256[i]);
    }

    return;
  }

  static void t_SHA256(string message, vector<int64_t> &digest, size_t t)
  {
    size_t times = t;
    for (size_t i = 0; i < times; i++)
    {
      SHA256(message, digest);
    }
  }

  static Matrix<Poly> customHash(Matrix<Poly> &A, string message, BigVector z)
  {
    usint m = 16;
    usint n = 8;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    auto params = make_shared<ILParams>(m, modulus, rootOfUnity);

    string A_str = "";
    for (size_t i = 0; i < A.GetRows(); i++)
    {
      for (size_t j = 0; j < A.GetCols(); j++)
      {
        for (size_t k = 0; k < n; k++)
        {
          A_str += A(i, j)[k].ToString();
        }
      }
    }

    string z_str = "";
    for (size_t i = 0; i < z.GetLength(); i++)
    {
      z_str += z[i].ToString();
    }

    string hash_input = A_str + message + z_str;
    vector<int64_t> digestVector;
    size_t t = 10; // the output dimension of customHash function
    t_SHA256(hash_input, digestVector, t);
    // cout << digestVector.size() << endl;

    Matrix<int64_t> digestMatrix([]()
                                 { return 0; }, t, n);
    for (size_t i = 0; i < t; i++)
    {
      for (size_t j = 0; j < n; j++)
      {
        digestMatrix(i, j) = digestVector[i * n + j];
      }
    }
    // cout << "digestMatrix:" << endl;
    // cout << digestMatrix << endl;

    Matrix<Poly> result =
        SplitInt64AltIntoElements<Poly>(digestMatrix, n, params);
    result = result.Transpose();
    // cout << "result:" << endl;
    // cout << result << endl;

    // cout << "Ah:" << endl;
    // for (size_t i = 0; i < result.GetCols(); i++) {
    //   cout << result(0, i) << endl;
    // }
    // cout << endl;

    // cout << result.GetRows() << endl;
    // cout << result.GetCols() << endl;

    return result;
  }

public:
  static pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> TrapGen()
  {
    usint m = 16;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    double stddev = SIGMA;

    auto params = make_shared<ILParams>(m, modulus, rootOfUnity);
    pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapdoorA =
        RLWETrapdoorUtility<Poly>::TrapdoorGen(
            params, stddev); // A.first is the public element

    // cout << trapdoorA.first.GetRows() << endl;
    // cout << trapdoorA.first.GetCols() << endl;
    // cout << trapdoorA.second.m_r.GetRows() << endl;
    // cout << trapdoorA.second.m_r.GetCols() << endl;
    // cout << trapdoorA.second.m_e.GetRows() << endl;
    // cout << trapdoorA.second.m_e.GetCols() << endl;

    trapdoorA.first.SetFormat(Format::COEFFICIENT);
    trapdoorA.second.m_r.SetFormat(Format::COEFFICIENT);
    trapdoorA.second.m_e.SetFormat(Format::COEFFICIENT);

    return trapdoorA;
  }

  static Matrix<Poly> Hash(Matrix<Poly> &A, string message, BigVector &z_out,
                           Matrix<Poly> &e1_out, Matrix<Poly> &e2_out)
  {
    usint m = 16;
    usint n = 8;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    auto params = make_shared<ILParams>(m, modulus, rootOfUnity);

    // cout << A << endl;

    DiscreteUniformGenerator dug;
    dug.SetModulus(modulus);
    BigVector z = dug.GenerateVector(n);
    // cout << z_str << endl;
    Matrix<Poly> Ah = customHash(A, message, z);
    // cout << "Ah: " << Ah << endl;
    // cout << "Ah cols: " << Ah.GetCols() << endl;

    double stddev = SIGMA;
    // double val = modulus.ConvertToDouble();  // TODO get the next few lines
    // working in a single instance.
    // double logTwo = log(val - 1.0) / log(2) + 1.0;
    // usint k = (usint)floor(logTwo);  // =
    // this->m_cryptoParameters.GetModulus(); size_t count = 1000; double
    // SMOOTHING_PARAMETER = 6;
    DiscreteGaussianGenerator dggRejection(stddev);

    Matrix<int64_t> e1Matrix([]()
                             { return 0; }, A.GetCols(), n);
    Matrix<int64_t> e2Matrix([]()
                             { return 0; }, Ah.GetCols(), n);

    for (size_t i = 0; i < A.GetCols(); i++)
    {
      BigVector e1Vector = dggRejection.GenerateVector(n, modulus);
      for (size_t j = 0; j < n; j++)
      {
        e1Matrix(i, j) = e1Vector[j].ConvertToInt();
      }
    }

    for (size_t i = 0; i < Ah.GetCols(); i++)
    {
      BigVector e2Vector = dggRejection.GenerateVector(n, modulus);
      for (size_t j = 0; j < n; j++)
      {
        e2Matrix(i, j) = e2Vector[j].ConvertToInt();
      }
    }

    Matrix<Poly> e1MatrixPoly =
        SplitInt64AltIntoElements<Poly>(e1Matrix, n, params);
    Matrix<Poly> e2MatrixPoly =
        SplitInt64AltIntoElements<Poly>(e2Matrix, n, params);

    A.SetFormat(Format::EVALUATION);
    e1MatrixPoly.SetFormat(Format::EVALUATION);
    Ah.SetFormat(Format::EVALUATION);
    e2MatrixPoly.SetFormat(Format::EVALUATION);

    Matrix<Poly> h = A.Mult(e1MatrixPoly) + Ah.Mult(e2MatrixPoly);

    Serial::SerializeToFile("calculated_h.json", h, SerType::JSON);
    modifyJsonValue("calculated_h.json");
    Serial::DeserializeFromFile("calculated_h.json", h, SerType::JSON);

    A.SetFormat(Format::COEFFICIENT);
    e1MatrixPoly.SetFormat(Format::COEFFICIENT);
    Ah.SetFormat(Format::COEFFICIENT);
    e2MatrixPoly.SetFormat(Format::COEFFICIENT);
    h.SetFormat(Format::COEFFICIENT);

    z_out = z;
    e1_out = e1MatrixPoly;
    e2_out = e2MatrixPoly;

    return h;
  }

  static Matrix<Poly> fixedHash(Matrix<Poly> &A, string message, BigVector &z,
                                Matrix<Poly> &e1, Matrix<Poly> &e2)
  {
    usint m = 16;
    // usint n = 8;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    auto params = make_shared<ILParams>(m, modulus, rootOfUnity);

    Matrix<Poly> Ah = customHash(A, message, z);

    A.SetFormat(Format::EVALUATION);
    e1.SetFormat(Format::EVALUATION);
    Ah.SetFormat(Format::EVALUATION);
    e2.SetFormat(Format::EVALUATION);

    Matrix<Poly> h = A.Mult(e1) + Ah.Mult(e2);

    Serial::SerializeToFile("calculated_h.json", h, SerType::JSON);
    modifyJsonValue("calculated_h.json");
    Serial::DeserializeFromFile("calculated_h.json", h, SerType::JSON);

    A.SetFormat(Format::COEFFICIENT);
    e1.SetFormat(Format::COEFFICIENT);
    Ah.SetFormat(Format::COEFFICIENT);
    e2.SetFormat(Format::COEFFICIENT);
    h.SetFormat(Format::COEFFICIENT);

    // cout << "fixedHash h: " << h << endl;

    return h;
  }

  static bool Verify(Matrix<Poly> &A, Matrix<Poly> &h, string message,
                     BigVector &z, Matrix<Poly> &e1, Matrix<Poly> &e2)
  {
    usint m = 16;
    // usint n = 8;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    auto params = make_shared<ILParams>(m, modulus, rootOfUnity);

    Matrix<Poly> Ah = customHash(A, message, z);
    // cout << "z: " << z << endl;
    // cout << "Ah:" << Ah << endl;

    A.SetFormat(Format::EVALUATION);
    e1.SetFormat(Format::EVALUATION);
    Ah.SetFormat(Format::EVALUATION);
    e2.SetFormat(Format::EVALUATION);
    h.SetFormat(Format::EVALUATION);

    Matrix<Poly> h_prime = A.Mult(e1) + Ah.Mult(e2);
    Serial::SerializeToFile("calculated_h.json", h_prime, SerType::JSON);
    modifyJsonValue("calculated_h.json");
    Serial::DeserializeFromFile("calculated_h.json", h_prime, SerType::JSON);

    A.SetFormat(Format::COEFFICIENT);
    e1.SetFormat(Format::COEFFICIENT);
    Ah.SetFormat(Format::COEFFICIENT);
    e2.SetFormat(Format::COEFFICIENT);
    h.SetFormat(Format::COEFFICIENT);
    h_prime.SetFormat(Format::COEFFICIENT);

    return h == h_prime;
  }

  static void Adapt(Matrix<Poly> A, RLWETrapdoorPair<Poly> trapdoor,
                    Matrix<Poly> &h, string message, BigVector &z,
                    Matrix<Poly> &e1, Matrix<Poly> &e2, string new_message,
                    BigVector &z_out, Matrix<Poly> &e1_out,
                    Matrix<Poly> &e2_out)
  {
    if (!Verify(A, h, message, z, e1, e2))
    {
      cout << "Invalid input" << endl;
      return;
    }

    usint m = 16;                   // m次分圆多项式
    usint n = 8;                    // 多项式的次数
    BigInteger modulus("67108913"); // 多项式系数的模数
    BigInteger rootOfUnity(
        "61564");                           // m次单位根    rootOfUnity ^ m = 1 mod modulus
    double stddev = SIGMA;                  // 标准差
    double val = modulus.ConvertToDouble(); // TODO get the next few lines
                                            // working in a single instance.
    double logTwo = log(val - 1.0) / log(2) + 1.0;
    usint k = (usint)floor(logTwo); // = this->m_cryptoParameters.GetModulus();

    auto params = make_shared<ILParams>(m, modulus, rootOfUnity);

    DiscreteUniformGenerator dug;
    dug.SetModulus(modulus);
    BigVector new_z = dug.GenerateVector(n);

    Matrix<Poly> new_Ah = customHash(A, new_message, new_z);

    DiscreteGaussianGenerator dggRejection(stddev);
    Matrix<int64_t> new_e2Matrix([]()
                                 { return 0; }, new_Ah.GetCols(), n);

    for (size_t i = 0; i < new_Ah.GetCols(); i++)
    {
      BigVector new_e2Vector = dggRejection.GenerateVector(n, modulus);
      for (size_t j = 0; j < n; j++)
      {
        new_e2Matrix(i, j) = new_e2Vector[j].ConvertToInt();
      }
    }

    Matrix<Poly> new_e2MatrixPoly =
        SplitInt64AltIntoElements<Poly>(new_e2Matrix, n, params);

    Poly::DggType dgg(stddev);
    uint32_t base = 2;
    double c = (base + 1) * SIGMA;
    double s = SPECTRAL_BOUND(n, k, base);
    Poly::DggType dggLargeSigma(sqrt(s * s - c * c));

    h.SetFormat(Format::EVALUATION);
    cout << "eval old hash: " << h << endl;
    new_Ah.SetFormat(Format::EVALUATION);
    new_e2MatrixPoly.SetFormat(Format::EVALUATION);

    Matrix<Poly> u = h - new_Ah.Mult(new_e2MatrixPoly);
    Poly u_poly = u(0, 0);
    u_poly.SetFormat(Format::EVALUATION);

    A.SetFormat(Format::EVALUATION);
    trapdoor.m_r.SetFormat(Format::EVALUATION);
    trapdoor.m_e.SetFormat(Format::EVALUATION);

    cout << "A: " << A << endl;
    cout << "trapdoor_e: " << trapdoor.m_e << endl;
    cout << "trapdoor_r: " << trapdoor.m_r << endl;
    cout << "u_poly: " << u_poly << endl;

    Matrix<Poly> new_e1MatrixPoly = RLWETrapdoorUtility<Poly>::GaussSamp(
        n, k, A, trapdoor, u_poly, dgg, dggLargeSigma);

    cout << "sampling phase completed" << endl;

    cout << "new_e1MatrixPoly: " << new_e1MatrixPoly << endl;
    cout << "new_Ah: " << new_Ah << endl;
    cout << "new_e2MatrixPoly: " << new_e2MatrixPoly << endl;

    auto manual_new_h = A * new_e1MatrixPoly + new_Ah * new_e2MatrixPoly;
    cout << "manual_new_h: " << manual_new_h << endl;
    Serial::SerializeToFile("calculated_h.json", manual_new_h, SerType::JSON);
    modifyJsonValue("calculated_h.json");
    Serial::DeserializeFromFile("calculated_h.json", manual_new_h,
                                SerType::JSON);

    A.SetFormat(Format::COEFFICIENT);
    trapdoor.m_r.SetFormat(Format::COEFFICIENT);
    trapdoor.m_e.SetFormat(Format::COEFFICIENT);
    e1.SetFormat(Format::COEFFICIENT);
    e2.SetFormat(Format::COEFFICIENT);
    h.SetFormat(Format::COEFFICIENT);
    new_Ah.SetFormat(Format::COEFFICIENT);
    new_e1MatrixPoly.SetFormat(Format::COEFFICIENT);
    new_e2MatrixPoly.SetFormat(Format::COEFFICIENT);

    z_out = new_z;
    e1_out = new_e1MatrixPoly;
    e2_out = new_e2MatrixPoly;

    return;
  }
};

Napi::Array BigVectorToNapiArray(Napi::Env env, BigVector vector)
{
  Napi::Array array = Napi::Array::New(env);
  for (size_t i = 0; i < vector.GetLength(); i++)
  {
    array.Set(i, Napi::Number::New(env, vector[i].ConvertToInt()));
  }
  return array;
}

Napi::Array MatrixToNapiArray(Napi::Env env, Matrix<Poly> matrix)
{
  Napi::Array array = Napi::Array::New(env);
  for (size_t i = 0; i < matrix.GetRows(); i++)
  {
    Napi::Array row = Napi::Array::New(env);
    for (size_t j = 0; j < matrix.GetCols(); j++)
    {
      Napi::Array element = Napi::Array::New(env);
      for (size_t k = 0; k < matrix(i, j).GetLength(); k++)
      {
        element.Set(k, Napi::Number::New(env, matrix(i, j)[k].ConvertToInt()));
      }
      row.Set(j, element);
    }
    array.Set(i, row);
  }
  return array;
}

Napi::Object RLWETrapdoorPairToNapiObject(Napi::Env env,
                                          RLWETrapdoorPair<Poly> trapdoor)
{
  Napi::Object obj = Napi::Object::New(env);
  obj.Set("r", MatrixToNapiArray(env, trapdoor.m_r));
  obj.Set("e", MatrixToNapiArray(env, trapdoor.m_e));
  return obj;
}

BigVector NapiArrayToBigVector(Napi::Env env, Napi::Array array)
{
  BigInteger modulus("67108913");
  size_t length = array.Length();
  BigVector vector(length, modulus);
  for (size_t i = 0; i < length; i++)
  {
    vector[i] = BigInteger(array.Get(i).As<Napi::Number>().Int64Value());
  }
  return vector;
}

Matrix<Poly> SingleColNapiArrayToMatrix(Napi::Env env, Napi::Array array,
                                        size_t col = 0)
{
  size_t rows = array.Length();
  size_t degree = array.Get(uint32_t(0))
                      .As<Napi::Array>()
                      .Get(uint32_t(0))
                      .As<Napi::Array>()
                      .Length();

  // cout << "rows: " << rows << endl;
  // cout << "degree: " << degree << endl;

  Matrix<int64_t> matrix([]()
                         { return 0; }, rows, degree);
  for (size_t i = 0; i < rows; i++)
  {
    Napi::Array row = array.Get(i).As<Napi::Array>();
    Napi::Array element = row.Get(col).As<Napi::Array>();
    for (size_t k = 0; k < degree; k++)
    {
      matrix(i, k) = element.Get(k).As<Napi::Number>().Int64Value();
    }
  }

  usint m = 16;
  usint n = 8;
  BigInteger modulus("67108913");
  BigInteger rootOfUnity("61564");
  auto params = make_shared<ILParams>(m, modulus, rootOfUnity);

  Matrix<Poly> matrixPoly = SplitInt64AltIntoElements<Poly>(matrix, n, params);
  return matrixPoly;
}

Matrix<Poly> MultColNapiArrayToMatrix(Napi::Env env, Napi::Array array)
{
  size_t rows = array.Length();
  size_t cols = array.Get(uint32_t(0)).As<Napi::Array>().Length();

  // cout << "rows: " << rows << endl;
  // cout << "cols: " << cols << endl;

  Matrix<Poly> matrixPoly = SingleColNapiArrayToMatrix(env, array, 0);
  for (size_t i = 0; i < rows; i++)
  {
    for (size_t j = 1; j < cols; j++)
    {
      matrixPoly.HStack(SingleColNapiArrayToMatrix(env, array, j));
    }
  }
  return matrixPoly;
}

Napi::Object SetupWrapped(const Napi::CallbackInfo &info)
{
  Napi::Env env = info.Env();
  pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapdoorA =
      ChameleonHash::TrapGen();
  string message = info[0].As<Napi::String>().Utf8Value();
  BigVector z;
  Matrix<Poly> e1;
  Matrix<Poly> e2;
  Matrix<Poly> h = ChameleonHash::Hash(trapdoorA.first, message, z, e1, e2);
  Napi::Object obj = Napi::Object::New(env);

  cout << "setupWrapped h: " << h << endl;

  obj.Set("A", MatrixToNapiArray(env, trapdoorA.first));
  obj.Set("trapdoor", RLWETrapdoorPairToNapiObject(env, trapdoorA.second));
  obj.Set("h", MatrixToNapiArray(env, h));
  obj.Set("z", BigVectorToNapiArray(env, z));
  obj.Set("e1", MatrixToNapiArray(env, e1));
  obj.Set("e2", MatrixToNapiArray(env, e2));
  return obj;
}

Napi::Object fixedHashWrapped(const Napi::CallbackInfo &info)
{
  if (info.Length() != 5)
  {
    cout << "wrong info length" << endl;
  }

  Napi::Env env = info.Env();
  Matrix<Poly> A = MultColNapiArrayToMatrix(env, info[0].As<Napi::Array>());
  BigVector z = NapiArrayToBigVector(env, info[1].As<Napi::Array>());
  Matrix<Poly> e1 = SingleColNapiArrayToMatrix(env, info[2].As<Napi::Array>());
  Matrix<Poly> e2 = SingleColNapiArrayToMatrix(env, info[3].As<Napi::Array>());
  string message = info[4].As<Napi::String>().Utf8Value();
  Matrix<Poly> h = ChameleonHash::fixedHash(A, message, z, e1, e2);

  cout << "fixedHashWrapped h: " << h << endl;

  Napi::Object obj = Napi::Object::New(env);
  obj.Set("h", MatrixToNapiArray(env, h));
  obj.Set("z", BigVectorToNapiArray(env, z));
  obj.Set("e1", MatrixToNapiArray(env, e1));
  obj.Set("e2", MatrixToNapiArray(env, e2));
  return obj;
}

Napi::Object AdaptWrapped(const Napi::CallbackInfo &info)
{
  if (info.Length() != 9)
  {
    cout << "wrong info length" << endl;
  }

  Napi::Env env = info.Env();
  Matrix<Poly> A = MultColNapiArrayToMatrix(env, info[0].As<Napi::Array>());
  Matrix<Poly> trapdoor_r =
      MultColNapiArrayToMatrix(env, info[1].As<Napi::Array>());
  Matrix<Poly> trapdoor_e =
      MultColNapiArrayToMatrix(env, info[2].As<Napi::Array>());
  BigVector z = NapiArrayToBigVector(env, info[3].As<Napi::Array>());
  Matrix<Poly> e1 = MultColNapiArrayToMatrix(env, info[4].As<Napi::Array>());
  Matrix<Poly> e2 = MultColNapiArrayToMatrix(env, info[5].As<Napi::Array>());
  string message = info[6].As<Napi::String>().Utf8Value();
  Matrix<Poly> h = SingleColNapiArrayToMatrix(env, info[7].As<Napi::Array>());
  string new_message = info[8].As<Napi::String>().Utf8Value();

  BigVector z_out;
  Matrix<Poly> e1_out;
  Matrix<Poly> e2_out;

  RLWETrapdoorPair<Poly> trapdoor = {trapdoor_r, trapdoor_e};

  ChameleonHash::Adapt(A, trapdoor, h, message, z, e1, e2, new_message, z_out,
                       e1_out, e2_out);

  auto new_h = ChameleonHash::fixedHash(A, new_message, z_out, e1_out, e2_out);
  cout << "adaptwrapped new hash: " << new_h << endl;

  Napi::Object obj = Napi::Object::New(env);
  obj.Set("new_z", BigVectorToNapiArray(env, z_out));
  obj.Set("new_e1", MatrixToNapiArray(env, e1_out));
  obj.Set("new_e2", MatrixToNapiArray(env, e2_out));
  obj.Set("new_h", MatrixToNapiArray(env, new_h));
  return obj;
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
  exports.Set("Setup", Napi::Function::New(env, SetupWrapped));
  exports.Set("Hash", Napi::Function::New(env, fixedHashWrapped));
  exports.Set("Adapt", Napi::Function::New(env, AdaptWrapped));
  return exports;
}

NODE_API_MODULE(addon, Init)