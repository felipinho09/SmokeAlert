/*
 * smoke_cli.cpp - Cliente do Smoke Alert em C++17 (sem bibliotecas externas)
 *
 * Voce digita so o comando (PING, STATUS, INFO). O programa:
 *   1. monta a mensagem  SEQUENCIA|COMANDO|HMAC-SHA256
 *   2. envia ao broker MQTT (protocolo MQTT 3.1.1 implementado aqui mesmo)
 *   3. aguarda a resposta do ESP32 e verifica a assinatura dela
 *
 * Compilar:
 *   Linux / macOS:   g++ -std=c++17 -O2 -Wall -o smoke_cli smoke_cli.cpp
 *   Windows (MinGW): g++ -std=c++17 -O2 -Wall -o smoke_cli.exe smoke_cli.cpp -lws2_32
 *   Windows (MSVC):  cl /EHsc /std:c++17 smoke_cli.cpp ws2_32.lib
 *
 * Usar:
 *   ./smoke_cli            (modo interativo)
 *   ./smoke_cli INFO       (envia um comando e mostra a resposta)
 *
 * Variaveis de ambiente opcionais:
 *   SMOKE_BROKER, SMOKE_PORTA, SMOKE_PREFIXO
 *   SMOKE_TIMEOUT=30   (segundos de espera pela resposta; padrao 15)
 *   SMOKE_DEBUG=1      (mostra todas as mensagens recebidas do broker)
 *
 * IMPORTANTE: guarde este arquivo na pasta "cliente/", longe do sketch.ino.
 * Ele roda no PC; se entrar no projeto do ESP32/Wokwi, causa erros de compilacao.
 */

// No Windows, estas definicoes precisam vir ANTES de qualquer #include.
// O MinGW antigo define _WIN32_WINNT=0x0400 ao ler os cabecalhos do C++,
// o que esconde getaddrinfo/freeaddrinfo.
#ifdef _WIN32
  #ifdef _WIN32_WINNT
    #undef _WIN32_WINNT
  #endif
  #define _WIN32_WINNT 0x0601
  #ifdef WINVER
    #undef WINVER
  #endif
  #define WINVER 0x0601
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using sock_t = SOCKET;
  constexpr sock_t SOCK_INVALIDO = INVALID_SOCKET;
  inline void fechar_sock(sock_t s) { closesocket(s); }
#else
  #include <netdb.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <sys/types.h>
  #include <unistd.h>
  using sock_t = int;
  constexpr sock_t SOCK_INVALIDO = -1;
  inline void fechar_sock(sock_t s) { ::close(s); }
#endif

#ifdef MSG_NOSIGNAL
  constexpr int FLAGS_ENVIO = MSG_NOSIGNAL;
#else
  constexpr int FLAGS_ENVIO = 0;
#endif

// ---- Configuracao (deve ser igual ao sketch) ----
namespace config {
    const std::string BROKER_PADRAO  = "test.mosquitto.org";
    const std::string PORTA_PADRAO   = "1883";
    const std::string PREFIXO_PADRAO = "smoke-alert/equipe01";   // troque se mudou os topicos
    const std::string CHAVE          = "SmokeAlert_Chave_Teste_2026";
    constexpr int TEMPO_RESPOSTA_PADRAO_S = 15;   // pode mudar com SMOKE_TIMEOUT
    constexpr size_t MAX_PACOTE      = 4096;
}

static int  g_tempo_resposta_s = config::TEMPO_RESPOSTA_PADRAO_S;
static bool g_debug = false;   // SMOKE_DEBUG=1 mostra tudo que chega do broker

// ========================================================================
// SHA-256 e HMAC-SHA256
// ========================================================================

namespace cripto {

constexpr std::array<uint32_t, 64> K256 = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

class Sha256 {
public:
    Sha256() : estado_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} {}

    void atualizar(const uint8_t* dados, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            bloco_[tam_bloco_++] = dados[i];
            if (tam_bloco_ == 64) {
                processar();
                bits_ += 512;
                tam_bloco_ = 0;
            }
        }
    }

    std::array<uint8_t, 32> finalizar() {
        uint32_t i = tam_bloco_;

        bloco_[i++] = 0x80;
        if (tam_bloco_ < 56) {
            while (i < 56) bloco_[i++] = 0;
        } else {
            while (i < 64) bloco_[i++] = 0;
            processar();
            std::fill(bloco_.begin(), bloco_.begin() + 56, 0);
        }

        bits_ += static_cast<uint64_t>(tam_bloco_) * 8;
        for (int k = 0; k < 8; ++k) {
            bloco_[63 - k] = static_cast<uint8_t>(bits_ >> (8 * k));
        }
        processar();

        std::array<uint8_t, 32> saida{};
        for (int k = 0; k < 8; ++k) {
            for (int j = 0; j < 4; ++j) {
                saida[j + 4 * k] = static_cast<uint8_t>((estado_[k] >> (24 - j * 8)) & 0xff);
            }
        }
        return saida;
    }

private:
    void processar() {
        std::array<uint32_t, 64> m{};

        for (int i = 0, j = 0; i < 16; ++i, j += 4) {
            m[i] = (static_cast<uint32_t>(bloco_[j]) << 24) | (static_cast<uint32_t>(bloco_[j + 1]) << 16) |
                   (static_cast<uint32_t>(bloco_[j + 2]) << 8) | static_cast<uint32_t>(bloco_[j + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
            uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
            m[i] = m[i - 16] + s0 + m[i - 7] + s1;
        }

        uint32_t a = estado_[0], b = estado_[1], c = estado_[2], d = estado_[3];
        uint32_t e = estado_[4], f = estado_[5], g = estado_[6], h = estado_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1  = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch  = (e & f) ^ (~e & g);
            uint32_t S0  = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t1  = h + S1 + ch + K256[i] + m[i];
            uint32_t t2  = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        estado_[0] += a; estado_[1] += b; estado_[2] += c; estado_[3] += d;
        estado_[4] += e; estado_[5] += f; estado_[6] += g; estado_[7] += h;
    }

    std::array<uint8_t, 64> bloco_{};
    uint32_t tam_bloco_ = 0;
    uint64_t bits_ = 0;
    std::array<uint32_t, 8> estado_;
};

inline std::array<uint8_t, 32> hmac_sha256(const std::string& chave, const std::string& msg) {
    std::array<uint8_t, 64> k{}, ipad{}, opad{};

    if (chave.size() > 64) {
        Sha256 h;
        h.atualizar(reinterpret_cast<const uint8_t*>(chave.data()), chave.size());
        auto d = h.finalizar();
        std::copy(d.begin(), d.end(), k.begin());
    } else {
        std::copy(chave.begin(), chave.end(), k.begin());
    }

    for (size_t i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    Sha256 interno;
    interno.atualizar(ipad.data(), ipad.size());
    interno.atualizar(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    auto h_interno = interno.finalizar();

    Sha256 externo;
    externo.atualizar(opad.data(), opad.size());
    externo.atualizar(h_interno.data(), h_interno.size());
    return externo.finalizar();
}

// Assina o texto e devolve o HMAC em hexadecimal MAIUSCULO (64 caracteres)
inline std::string assinar(const std::string& texto) {
    static const char dig[] = "0123456789ABCDEF";
    auto h = hmac_sha256(config::CHAVE, texto);

    std::string hex;
    hex.reserve(64);
    for (uint8_t byte : h) {
        hex += dig[byte >> 4];
        hex += dig[byte & 0x0f];
    }
    return hex;
}

// Comparacao sem interrupcao antecipada (tempo constante)
inline bool iguais_const(const std::string& calculada, const std::string& recebida) {
    if (calculada.size() != recebida.size()) return false;

    unsigned char diferenca = 0;
    for (size_t i = 0; i < calculada.size(); ++i) {
        diferenca |= static_cast<unsigned char>(
            calculada[i] ^ std::toupper(static_cast<unsigned char>(recebida[i])));
    }
    return diferenca == 0;
}

} // namespace cripto

// ========================================================================
// Rede (socket RAII) e MQTT 3.1.1 minimo
// ========================================================================

class ErroRede : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

#ifdef _WIN32
class WinsockInit {
public:
    WinsockInit() {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) throw ErroRede("Falha ao iniciar o Winsock.");
    }
    ~WinsockInit() { WSACleanup(); }
};
#endif

class Conexao {
public:
    Conexao(const std::string& host, const std::string& porta) {
        addrinfo dica{}, *lista = nullptr;
        dica.ai_family = AF_UNSPEC;
        dica.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(host.c_str(), porta.c_str(), &dica, &lista) != 0) {
            throw ErroRede("Nao foi possivel resolver " + host);
        }

        for (addrinfo* p = lista; p != nullptr; p = p->ai_next) {
            sock_ = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (sock_ == SOCK_INVALIDO) continue;
            if (::connect(sock_, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) break;
            fechar_sock(sock_);
            sock_ = SOCK_INVALIDO;
        }
        freeaddrinfo(lista);

        if (sock_ == SOCK_INVALIDO) {
            throw ErroRede("Nao foi possivel conectar em " + host + ":" + porta);
        }

        // Evita travar para sempre em leituras que nao chegam
#ifdef _WIN32
        DWORD ms = 8000;
        setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
#else
        timeval tv{};
        tv.tv_sec = 8;
        setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

    ~Conexao() {
        if (sock_ != SOCK_INVALIDO) fechar_sock(sock_);
    }

    Conexao(const Conexao&) = delete;
    Conexao& operator=(const Conexao&) = delete;

    void enviar(const std::vector<uint8_t>& dados) {
        size_t enviado = 0;
        while (enviado < dados.size()) {
            int r = static_cast<int>(::send(sock_,
                                            reinterpret_cast<const char*>(dados.data()) + enviado,
                                            static_cast<int>(dados.size() - enviado), FLAGS_ENVIO));
            if (r <= 0) throw ErroRede("Falha ao enviar dados ao broker.");
            enviado += static_cast<size_t>(r);
        }
    }

    void ler_exato(uint8_t* buf, size_t n) {
        size_t lido = 0;
        while (lido < n) {
            int r = static_cast<int>(::recv(sock_, reinterpret_cast<char*>(buf) + lido,
                                            static_cast<int>(n - lido), 0));
            if (r <= 0) throw ErroRede("Conexao encerrada ou tempo esgotado.");
            lido += static_cast<size_t>(r);
        }
    }

    bool esperar_dados(int ms) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock_, &fds);

        timeval tv{};
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;

        return ::select(static_cast<int>(sock_) + 1, &fds, nullptr, nullptr, &tv) > 0;
    }

private:
    sock_t sock_ = SOCK_INVALIDO;
};

struct Pacote {
    uint8_t cabecalho = 0;
    std::vector<uint8_t> corpo;

    int tipo() const { return cabecalho >> 4; }
};

// Codifica o "Remaining Length" do MQTT
std::vector<uint8_t> codificar_tamanho(size_t tam) {
    std::vector<uint8_t> saida;
    do {
        uint8_t d = static_cast<uint8_t>(tam % 128);
        tam /= 128;
        if (tam > 0) d |= 0x80;
        saida.push_back(d);
    } while (tam > 0);
    return saida;
}

void adicionar_texto(std::vector<uint8_t>& v, const std::string& s) {
    v.push_back(static_cast<uint8_t>(s.size() >> 8));
    v.push_back(static_cast<uint8_t>(s.size() & 0xff));
    v.insert(v.end(), s.begin(), s.end());
}

Pacote ler_pacote(Conexao& con) {
    Pacote p;
    uint8_t b = 0;
    size_t mult = 1, valor = 0;
    int n = 0;

    con.ler_exato(&p.cabecalho, 1);

    do {
        con.ler_exato(&b, 1);
        valor += static_cast<size_t>(b & 0x7f) * mult;
        mult *= 128;
        if (++n > 4) throw ErroRede("Pacote MQTT malformado.");
    } while (b & 0x80);

    if (valor > config::MAX_PACOTE) throw ErroRede("Pacote MQTT grande demais.");

    p.corpo.resize(valor);
    if (valor > 0) con.ler_exato(p.corpo.data(), valor);
    return p;
}

std::vector<uint8_t> montar_connect(const std::string& id_cliente) {
    std::vector<uint8_t> corpo;
    adicionar_texto(corpo, "MQTT");
    corpo.push_back(0x04);              // nivel do protocolo 3.1.1
    corpo.push_back(0x02);              // clean session
    corpo.push_back(0x00);              // keepalive 30 s
    corpo.push_back(0x1e);
    adicionar_texto(corpo, id_cliente);

    std::vector<uint8_t> pacote{0x10};
    auto tam = codificar_tamanho(corpo.size());
    pacote.insert(pacote.end(), tam.begin(), tam.end());
    pacote.insert(pacote.end(), corpo.begin(), corpo.end());
    return pacote;
}

std::vector<uint8_t> montar_subscribe(const std::string& topico) {
    std::vector<uint8_t> corpo{0x00, 0x01};   // packet id
    adicionar_texto(corpo, topico);
    corpo.push_back(0x00);                    // QoS 0

    std::vector<uint8_t> pacote{0x82};
    auto tam = codificar_tamanho(corpo.size());
    pacote.insert(pacote.end(), tam.begin(), tam.end());
    pacote.insert(pacote.end(), corpo.begin(), corpo.end());
    return pacote;
}

std::vector<uint8_t> montar_publish(const std::string& topico, const std::string& mensagem) {
    std::vector<uint8_t> corpo;
    adicionar_texto(corpo, topico);
    corpo.insert(corpo.end(), mensagem.begin(), mensagem.end());

    std::vector<uint8_t> pacote{0x30};        // QoS 0, sem retain
    auto tam = codificar_tamanho(corpo.size());
    pacote.insert(pacote.end(), tam.begin(), tam.end());
    pacote.insert(pacote.end(), corpo.begin(), corpo.end());
    return pacote;
}

// Sequencia baseada no horario: sempre cresce, mesmo entre execucoes
unsigned long proxima_seq() {
    static unsigned long ultima = 0;
    auto agora = static_cast<unsigned long>(std::time(nullptr));
    ultima = (agora > ultima) ? agora : ultima + 1;
    return ultima;
}

// Trata um PUBLISH recebido. Devolve true se era a resposta ao nosso comando.
bool tratar_publish(const Pacote& p, const std::string& t_resp, unsigned long nossa_seq) {
    const auto& c = p.corpo;
    int qos = (p.cabecalho >> 1) & 3;

    if (c.size() < 2) return false;
    size_t tam_topico = (static_cast<size_t>(c[0]) << 8) | c[1];
    if (2 + tam_topico > c.size()) return false;

    std::string topico(c.begin() + 2, c.begin() + 2 + static_cast<std::ptrdiff_t>(tam_topico));
    size_t pos = 2 + tam_topico + (qos > 0 ? 2 : 0);
    if (pos > c.size()) return false;

    std::string payload(c.begin() + static_cast<std::ptrdiff_t>(pos), c.end());

    if (g_debug) std::cout << "[debug] recebido em " << topico << ": " << payload << "\n";

    if (topico != t_resp) return false;

    // Formato: SEQUENCIA|RESPOSTA|HMAC
    size_t p1 = payload.find('|');
    size_t p2 = payload.rfind('|');
    if (p1 == std::string::npos || p2 == std::string::npos || p2 <= p1) return false;

    std::string seq_txt = payload.substr(0, p1);
    std::string resposta = payload.substr(p1 + 1, p2 - p1 - 1);
    std::string assinatura = payload.substr(p2 + 1);

    if (seq_txt != std::to_string(nossa_seq)) {   // resposta de outro comando
        if (g_debug) std::cout << "[debug] ignorada: sequencia " << seq_txt << " (a nossa e " << nossa_seq << ")\n";
        return false;
    }

    std::string esperada = cripto::assinar(seq_txt + ":" + resposta);

    if (cripto::iguais_const(esperada, assinatura)) {
        std::cout << "[resposta AUTENTICA] " << resposta << "\n";
    } else {
        std::cout << "[ASSINATURA INVALIDA] resposta descartada: " << resposta << "\n";
    }
    return true;
}

// Uma sessao completa: conecta, assina, envia o comando e aguarda a resposta
bool executar_comando(const std::string& host, const std::string& porta,
                      const std::string& prefixo, const std::string& comando) {
    const std::string t_cmd = prefixo + "/comandos";
    const std::string t_resp = prefixo + "/respostas";

    try {
        std::random_device rd;
        char id_buf[40];
        std::snprintf(id_buf, sizeof(id_buf), "smokecli-%08x", static_cast<unsigned>(rd()) ^ static_cast<unsigned>(std::time(nullptr)));

        Conexao con(host, porta);

        // CONNECT / CONNACK
        con.enviar(montar_connect(id_buf));
        Pacote connack = ler_pacote(con);
        if (connack.tipo() != 2 || connack.corpo.size() < 2 || connack.corpo[1] != 0) {
            std::cout << "O broker recusou a conexao MQTT.\n";
            return false;
        }

        // SUBSCRIBE / SUBACK (antes de publicar, para nao perder a resposta)
        con.enviar(montar_subscribe(t_resp));
        for (;;) {
            Pacote p = ler_pacote(con);
            if (p.tipo() == 9) break;
        }

        // Monta e envia a mensagem assinada
        unsigned long seq = proxima_seq();
        std::string assinada = std::to_string(seq) + ":" + comando;
        std::string mensagem = std::to_string(seq) + "|" + comando + "|" + cripto::assinar(assinada);

        con.enviar(montar_publish(t_cmd, mensagem));
        std::cout << "Enviado: " << comando << " (sequencia " << seq << ")\n";

        // Aguarda a resposta
        std::cout << "Aguardando resposta (ate " << g_tempo_resposta_s << " s)...\n";
        bool recebeu = false;
        auto inicio = std::chrono::steady_clock::now();
        std::time_t limite = std::time(nullptr) + g_tempo_resposta_s;

        while (!recebeu) {
            long restante_ms = static_cast<long>(limite - std::time(nullptr)) * 1000;
            if (restante_ms <= 0) break;
            if (!con.esperar_dados(static_cast<int>(restante_ms))) break;

            try {
                Pacote p = ler_pacote(con);
                if (p.tipo() == 3) {
                    recebeu = tratar_publish(p, t_resp, seq);
                } else if (g_debug) {
                    std::cout << "[debug] pacote MQTT tipo " << p.tipo() << "\n";
                }
            } catch (const ErroRede&) {
                break;   // conexao caiu: trata como "sem resposta"
            }
        }

        if (recebeu) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - inicio).count();
            std::cout << "(resposta em " << ms << " ms)\n";
        } else {
            std::cout << "Sem resposta em " << g_tempo_resposta_s
                      << " s. O ESP32 esta ligado? O comando foi rejeitado? (veja o monitor serial)\n"
                      << "Dica: rode com SMOKE_DEBUG=1 para ver o que chega do broker.\n";
        }

        // DISCONNECT (educado, mas sem importar se falhar)
        try { con.enviar({0xE0, 0x00}); } catch (const ErroRede&) {}

        return recebeu;

    } catch (const ErroRede& e) {
        std::cout << "Erro: " << e.what() << "\n";
        return false;
    }
}

// ========================================================================
// Programa principal
// ========================================================================

std::string valor_ambiente(const char* nome, const std::string& padrao) {
    const char* v = std::getenv(nome);
    return (v != nullptr && *v != '\0') ? std::string(v) : padrao;
}

std::string maiusculas(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

std::string remover_bordas(const std::string& s) {
    size_t ini = s.find_first_not_of(" \t\r\n");
    if (ini == std::string::npos) return "";
    size_t fim = s.find_last_not_of(" \t\r\n");
    return s.substr(ini, fim - ini + 1);
}

bool comando_valido(const std::string& c) {
    if (c.empty() || c.size() > 32) return false;
    return std::all_of(c.begin(), c.end(), [](unsigned char ch) {
        return ch != '|' && std::isprint(ch);
    });
}

int main(int argc, char** argv) {
    const std::string host    = valor_ambiente("SMOKE_BROKER",  config::BROKER_PADRAO);
    const std::string porta   = valor_ambiente("SMOKE_PORTA",   config::PORTA_PADRAO);
    const std::string prefixo = valor_ambiente("SMOKE_PREFIXO", config::PREFIXO_PADRAO);

    g_debug = valor_ambiente("SMOKE_DEBUG", "0") != "0";
    int timeout = std::atoi(valor_ambiente("SMOKE_TIMEOUT", "0").c_str());
    if (timeout > 0) g_tempo_resposta_s = timeout;

    try {
#ifdef _WIN32
        WinsockInit winsock;
#endif

        // Modo de comando unico
        if (argc > 1) {
            std::string comando = maiusculas(remover_bordas(argv[1]));

            if (!comando_valido(comando)) {
                std::cout << "Comando invalido.\n";
                return 1;
            }
            return executar_comando(host, porta, prefixo, comando) ? 0 : 1;
        }

        // Modo interativo
        std::cout << "Smoke Alert - digite PING, STATUS ou INFO (SAIR para fechar)\n";

        std::string linha;
        for (;;) {
            std::cout << "> " << std::flush;
            if (!std::getline(std::cin, linha)) break;

            std::string comando = maiusculas(remover_bordas(linha));

            if (comando == "SAIR" || comando == "EXIT") break;
            if (comando.empty()) continue;
            if (!comando_valido(comando)) {
                std::cout << "Comando invalido (nao use o caractere '|').\n";
                continue;
            }

            executar_comando(host, porta, prefixo, comando);
        }

    } catch (const std::exception& e) {
        std::cout << "Erro: " << e.what() << "\n";
        return 1;
    }

    return 0;
}