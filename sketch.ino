#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <Preferences.h>
#include <string.h>
#include "mbedtls/md.h"

// ========================================
// CONFIGURACAO DOS PINOS
// ========================================

#define PIN_MQ2 34
#define PIN_DHT 4
#define PIN_BUZZER 25

#define LED_VERDE 18
#define LED_AMARELO 19
#define LED_VERMELHO 23

#define PIN_TAMPER 27

// ========================================
// LIMITES DOS SENSORES
// ========================================

#define LIMITE_ATENCAO 1500
#define LIMITE_ALERTA 2800

#define TEMP_ATENCAO 35.0
#define TEMP_ALERTA 50.0

// ========================================
// INTERVALOS (ms)
// ========================================

#define INTERVALO_LEITURA_MS   1000
#define INTERVALO_SENSORES_MS  5000
#define INTERVALO_RECONEXAO_WIFI_MS 10000
#define INTERVALO_RECONEXAO_MQTT_MS 5000

// ========================================
// CONFIGURACAO DO DHT22
// ========================================

#define TIPO_DHT DHT22

DHT dht(PIN_DHT, TIPO_DHT);

// ========================================
// CONFIGURACAO DO WIFI
// ========================================

const char* ssid = "Wokwi-GUEST";
const char* password = "";

// ========================================
// CONFIGURACAO MQTT
// ========================================

// Chave secreta HMAC de TESTE
const char* chaveSecreta = "SmokeAlert_Chave_Teste_2026";

const char* mqtt_server = "test.mosquitto.org";
const int mqtt_port = 1883;

const char* topico_comandos  = "smoke-alert/equipe01/comandos";
const char* topico_respostas = "smoke-alert/equipe01/respostas";
const char* topico_status    = "smoke-alert/equipe01/status";
const char* topico_sensores  = "smoke-alert/equipe01/sensores";

WiFiClient espClient;
PubSubClient mqtt(espClient);

// ========================================
// ESTADOS DO SISTEMA
// ========================================

enum Estado {
  ESTADO_NORMAL = 0,
  ESTADO_ATENCAO,
  ESTADO_ALERTA,
  ESTADO_VIOLACAO,
  ESTADO_FALHA_SENSOR
};

const char* nomeEstado(int estado) {
  switch (estado) {
    case ESTADO_NORMAL:       return "NORMAL";
    case ESTADO_ATENCAO:      return "ATENCAO";
    case ESTADO_ALERTA:       return "ALERTA";
    case ESTADO_VIOLACAO:     return "VIOLACAO";
    case ESTADO_FALHA_SENSOR: return "FALHA_SENSOR";
    default:                  return "DESCONHECIDO";
  }
}

int estadoAtual = -1;  // -1 = ainda nao classificado

// ========================================
// VARIAVEIS DE CONTROLE
// ========================================

bool gabineteAbertoAntes = false;
unsigned long totalViolacoes = 0;

unsigned long ultimaLeitura = 0;
unsigned long ultimoEnvioSensores = 0;
unsigned long ultimaTentativaWiFi = 0;
unsigned long ultimaTentativaMQTT = 0;

// Ultimo valor lido (usado na publicacao de sensores)
int ultimaFumaca = 0;
float ultimaTemp = NAN;
float ultimaUmid = NAN;

// ========================================
// AUTENTICACAO MQTT (sequencia persistente)
// ========================================

Preferences prefs;

// Ultima sequencia autenticada e aceita (salva na flash)
uint32_t ultimaSequencia = 0;

String gerarHMAC(String mensagem) {

  byte assinatura[32];

  const mbedtls_md_info_t* info =
    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (info == nullptr) {
    Serial.println("Erro: SHA-256 indisponivel!");
    return "";
  }

  int resultado = mbedtls_md_hmac(
    info,
    (const unsigned char*)chaveSecreta,
    strlen(chaveSecreta),
    (const unsigned char*)mensagem.c_str(),
    mensagem.length(),
    assinatura
  );

  if (resultado != 0) {
    Serial.println("Erro ao calcular HMAC!");
    return "";
  }

  String resultadoHex = "";

  for (int i = 0; i < 32; i++) {
    if (assinatura[i] < 16) {
      resultadoHex += "0";
    }
    resultadoHex += String(assinatura[i], HEX);
  }

  resultadoHex.toUpperCase();

  return resultadoHex;
}

bool validarHMAC(String mensagem, String assinaturaRecebida) {

  String assinaturaCalculada = gerarHMAC(mensagem);

  if (assinaturaCalculada.length() != 64) {
    return false;
  }

  if (assinaturaRecebida.length() != 64) {
    return false;
  }

  assinaturaRecebida.toUpperCase();

  // Comparacao sem interrupcao antecipada
  byte diferenca = 0;

  for (int i = 0; i < 64; i++) {
    diferenca |= assinaturaCalculada[i] ^ assinaturaRecebida[i];
  }

  return diferenca == 0;
}

// ========================================
// PUBLICAR RESPOSTA ASSINADA
// Formato: SEQUENCIA|RESPOSTA|HMAC
// HMAC calculado sobre "SEQUENCIA:RESPOSTA"
// (a resposta nao pode conter o caractere '|')
// ========================================

void publicarResposta(const String& sequenciaTexto, const String& texto) {

  String assinada = sequenciaTexto + ":" + texto;
  String mensagem = sequenciaTexto + "|" + texto + "|" + gerarHMAC(assinada);

  mqtt.publish(topico_respostas, mensagem.c_str());
}

// ========================================
// FUNCOES DE SAIDA (LEDS E BUZZER)
// ========================================

void apagaTudo() {

  digitalWrite(LED_VERDE, LOW);
  digitalWrite(LED_AMARELO, LOW);
  digitalWrite(LED_VERMELHO, LOW);

  noTone(PIN_BUZZER);
}

// Atualiza as saidas somente quando o estado muda
void aplicarEstado(int estado) {

  apagaTudo();

  switch (estado) {
    case ESTADO_VIOLACAO:
      digitalWrite(LED_VERMELHO, HIGH);
      tone(PIN_BUZZER, 2000);
      break;

    case ESTADO_FALHA_SENSOR:
      digitalWrite(LED_VERMELHO, HIGH);
      break;

    case ESTADO_ALERTA:
      digitalWrite(LED_VERMELHO, HIGH);
      tone(PIN_BUZZER, 1000);
      break;

    case ESTADO_ATENCAO:
      digitalWrite(LED_AMARELO, HIGH);
      break;

    default:
      digitalWrite(LED_VERDE, HIGH);
      break;
  }
}

// ========================================
// PUBLICACOES MQTT (status e sensores)
// ========================================

void publicarStatus() {

  if (!mqtt.connected() || estadoAtual < 0) {
    return;
  }

  // retained: quem se inscrever depois ainda recebe o ultimo estado
  mqtt.publish(topico_status, nomeEstado(estadoAtual), true);
}

void publicarSensores() {

  if (!mqtt.connected() || estadoAtual < 0) {
    return;
  }

  char tempTxt[12];
  char umidTxt[12];

  if (isnan(ultimaTemp)) strcpy(tempTxt, "null");
  else snprintf(tempTxt, sizeof(tempTxt), "%.1f", ultimaTemp);

  if (isnan(ultimaUmid)) strcpy(umidTxt, "null");
  else snprintf(umidTxt, sizeof(umidTxt), "%.1f", ultimaUmid);

  char json[200];

  snprintf(
    json, sizeof(json),
    "{\"estado\":\"%s\",\"fumaca\":%d,\"temp\":%s,\"umid\":%s,\"violacoes\":%lu}",
    nomeEstado(estadoAtual), ultimaFumaca, tempTxt, umidTxt, totalViolacoes
  );

  mqtt.publish(topico_sensores, json);
}

// ========================================
// CONEXOES (Wi-Fi e MQTT)
// ========================================

void conectarWiFi() {

  Serial.println("Conectando ao Wi-Fi...");

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("Wi-Fi conectado!");

  Serial.print("Endereco IP: ");
  Serial.println(WiFi.localIP());
}

void conectarMQTT() {

  Serial.println("Conectando ao MQTT...");

  // ID unico baseado no MAC do ESP32 (evita colisao no broker publico)
  String idCliente = "SmokeAlertEquipe01-" + String((uint32_t)ESP.getEfuseMac(), HEX);

  // Last Will: se o dispositivo cair, o broker publica OFFLINE no status
  bool ok = mqtt.connect(
    idCliente.c_str(),
    nullptr, nullptr,
    topico_status, 1, true, "OFFLINE"
  );

  if (ok) {

    Serial.println("MQTT conectado!");

    mqtt.subscribe(topico_comandos);
    Serial.println("Inscrito no topico de comandos!");

    // Informa o estado atual assim que reconectar
    publicarStatus();

  } else {

    Serial.print("Falha na conexao MQTT. Codigo: ");
    Serial.println(mqtt.state());
  }
}

// Mantem Wi-Fi e MQTT sem bloquear o loop principal
void manterConexoes() {

  unsigned long agora = millis();

  if (WiFi.status() != WL_CONNECTED) {

    if (agora - ultimaTentativaWiFi >= INTERVALO_RECONEXAO_WIFI_MS) {
      ultimaTentativaWiFi = agora;
      Serial.println("Wi-Fi desconectado. Tentando reconectar...");
      WiFi.disconnect();
      WiFi.begin(ssid, password);
    }

    return;
  }

  if (!mqtt.connected() && agora - ultimaTentativaMQTT >= INTERVALO_RECONEXAO_MQTT_MS) {
    ultimaTentativaMQTT = agora;
    conectarMQTT();
  }
}

// ========================================
// RECEBER E AUTENTICAR MENSAGENS MQTT
// Formato: SEQUENCIA|COMANDO|ASSINATURA
// HMAC sobre "SEQUENCIA:COMANDO" (comando em MAIUSCULAS)
// ========================================

void receberMensagem(char* topic, byte* payload, unsigned int length) {

  if (String(topic) != topico_comandos) {
    Serial.println("Topico nao autorizado!");
    return;
  }

  // Limite de tamanho para evitar mensagens absurdas
  if (length == 0 || length > 200) {
    Serial.println("Mensagem com tamanho invalido!");
    return;
  }

  String mensagem = "";

  for (unsigned int i = 0; i < length; i++) {
    mensagem += (char)payload[i];
  }

  Serial.println();
  Serial.println("===== AUTENTICACAO MQTT =====");

  int primeiroSeparador = mensagem.indexOf('|');
  int segundoSeparador = mensagem.indexOf('|', primeiroSeparador + 1);

  if (primeiroSeparador <= 0 || segundoSeparador <= primeiroSeparador + 1) {
    Serial.println("Mensagem em formato invalido!");
    return;
  }

  String sequenciaTexto = mensagem.substring(0, primeiroSeparador);

  String comando = mensagem.substring(
    primeiroSeparador + 1,
    segundoSeparador
  );

  String assinatura = mensagem.substring(segundoSeparador + 1);

  comando.trim();
  comando.toUpperCase();

  // Sequencia: apenas digitos, sem estouro de uint32_t
  uint32_t sequencia = 0;

  for (unsigned int i = 0; i < sequenciaTexto.length(); i++) {

    char caractere = sequenciaTexto[i];

    if (caractere < '0' || caractere > '9') {
      Serial.println("Sequencia invalida!");
      return;
    }

    uint32_t digito = caractere - '0';

    if (sequencia > (UINT32_MAX - digito) / 10) {
      Serial.println("Sequencia fora do limite!");
      return;
    }

    sequencia = sequencia * 10 + digito;
  }

  if (sequencia == 0) {
    Serial.println("Sequencia invalida!");
    return;
  }

  // Verifica a assinatura HMAC
  String mensagemAssinada = sequenciaTexto + ":" + comando;

  if (!validarHMAC(mensagemAssinada, assinatura)) {
    Serial.println("ASSINATURA INVALIDA!");
    Serial.println("Comando rejeitado!");
    return;
  }

  Serial.println("Assinatura HMAC valida!");

  // Protecao contra repeticao de mensagens
  if (sequencia <= ultimaSequencia) {
    Serial.println("REPLAY ATTACK DETECTADO!");
    Serial.println("Comando rejeitado!");
    return;
  }

  // Atualiza e SALVA na flash (sobrevive a reinicios)
  ultimaSequencia = sequencia;
  prefs.putUInt("seq", ultimaSequencia);

  Serial.println("Sequencia autorizada!");
  Serial.print("Comando: ");
  Serial.println(comando);

  // ======================================
  // EXECUCAO DOS COMANDOS AUTENTICADOS
  // (todas as respostas saem assinadas)
  // ======================================

  if (comando == "STATUS") {

    publicarResposta(sequenciaTexto, "Sistema Smoke Alert ativo! Estado: " + String(nomeEstado(estadoAtual)));
    Serial.println("Resposta STATUS enviada!");

  } else if (comando == "PING") {

    publicarResposta(sequenciaTexto, "PONG");
    Serial.println("Resposta PONG enviada!");

  } else if (comando == "INFO") {

    int fumaca = analogRead(PIN_MQ2);
    float temperatura = dht.readTemperature();
    float umidade = dht.readHumidity();

    String resposta = "Fumaca: " + String(fumaca);
    resposta += "; Temperatura: " + String(temperatura);
    resposta += " C; Umidade: " + String(umidade) + "%";

    publicarResposta(sequenciaTexto, resposta);
    Serial.println("Informacoes dos sensores enviadas!");

  } else {

    publicarResposta(sequenciaTexto, "Comando desconhecido!");
    Serial.println("Comando desconhecido!");
  }

  Serial.println("==============================");
}

// ========================================
// SETUP
// ========================================

void setup() {

  Serial.begin(115200);

  // Carrega a ultima sequencia aceita da flash
  prefs.begin("smokealert", false);
  ultimaSequencia = prefs.getUInt("seq", 0);

  Serial.print("Ultima sequencia salva: ");
  Serial.println(ultimaSequencia);

  String testeHMAC = gerarHMAC("STATUS");
  Serial.println("Teste HMAC:");
  Serial.println(testeHMAC);

  dht.begin();

  pinMode(LED_VERDE, OUTPUT);
  pinMode(LED_AMARELO, OUTPUT);
  pinMode(LED_VERMELHO, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_TAMPER, INPUT_PULLUP);

  Serial.println();
  Serial.println("================================");
  Serial.println("       SMOKE ALERT INICIADO");
  Serial.println("================================");

  conectarWiFi();

  mqtt.setServer(mqtt_server, mqtt_port);
  mqtt.setCallback(receberMensagem);
  mqtt.setBufferSize(512);
}

// ========================================
// LOOP PRINCIPAL (sem delay bloqueante)
// ========================================

void loop() {

  manterConexoes();
  mqtt.loop();

  unsigned long agora = millis();

  // Leitura e classificacao a cada INTERVALO_LEITURA_MS
  if (agora - ultimaLeitura < INTERVALO_LEITURA_MS) {
    return;
  }

  ultimaLeitura = agora;

  // ======================================
  // LEITURA DOS SENSORES
  // ======================================

  int fumaca = analogRead(PIN_MQ2);
  float temp = dht.readTemperature();
  float umid = dht.readHumidity();

  bool gabineteAberto = (digitalRead(PIN_TAMPER) == HIGH);

  ultimaFumaca = fumaca;
  ultimaTemp = temp;
  ultimaUmid = umid;

  // ======================================
  // REGISTRO DE VIOLACOES
  // ======================================

  if (gabineteAberto && !gabineteAbertoAntes) {

    totalViolacoes++;

    Serial.print("[EVENTO] VIOLACAO: gabinete aberto | t=");
    Serial.print(millis());
    Serial.print(" ms | total=");
    Serial.println(totalViolacoes);

  } else if (!gabineteAberto && gabineteAbertoAntes) {

    Serial.print("[EVENTO] Gabinete fechado | t=");
    Serial.print(millis());
    Serial.println(" ms");
  }

  gabineteAbertoAntes = gabineteAberto;

  // ======================================
  // CLASSIFICACAO DOS ESTADOS (por prioridade)
  // ======================================

  int novoEstado;

  if (gabineteAberto) {
    novoEstado = ESTADO_VIOLACAO;
  } else if (isnan(temp) || isnan(umid)) {
    novoEstado = ESTADO_FALHA_SENSOR;
  } else if (fumaca >= LIMITE_ALERTA || temp >= TEMP_ALERTA) {
    novoEstado = ESTADO_ALERTA;
  } else if (fumaca >= LIMITE_ATENCAO || temp >= TEMP_ATENCAO) {
    novoEstado = ESTADO_ATENCAO;
  } else {
    novoEstado = ESTADO_NORMAL;
  }

  // Aplica saidas e publica status apenas quando o estado muda
  if (novoEstado != estadoAtual) {

    estadoAtual = novoEstado;

    aplicarEstado(estadoAtual);
    publicarStatus();

    Serial.print("[ESTADO] -> ");
    Serial.println(nomeEstado(estadoAtual));
  }

  // ======================================
  // EXIBICAO NO MONITOR SERIAL
  // ======================================

  Serial.print("Estado: ");
  Serial.print(nomeEstado(estadoAtual));
  Serial.print(" | Fumaca: ");
  Serial.print(fumaca);
  Serial.print(" | Temp: ");
  Serial.print(temp);
  Serial.print(" C | Umid: ");
  Serial.print(umid);
  Serial.print(" % | Violacoes: ");
  Serial.println(totalViolacoes);

  // ======================================
  // TELEMETRIA PERIODICA
  // ======================================

  if (agora - ultimoEnvioSensores >= INTERVALO_SENSORES_MS) {
    ultimoEnvioSensores = agora;
    publicarSensores();
  }
}
