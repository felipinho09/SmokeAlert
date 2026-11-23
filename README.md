# [Nome do Projeto]: [Subtítulo Criativo]

> Projeto prático de IoT e Segurança da Informação desenvolvido na disciplina de Algoritmos e Estrutura de Dados.


 ## 👥 Integrantes da Equipe
- Felipe Mota (felipeeufrasiomota@gmail.com / felipinho09)
- Matheus Mazony (matheusmazony@gmail.com / GitHub)
- João Henrique Bosshard (joao.bosshard@upe.br / matheusmazony-ops)
- Mateus Borba ()
- Walisson Diogo ( / Waly16)
---

 
## 📖 1. Contexto e História (O Problema)
*Descreva qual cenário de ameaça ou problema de segurança física/digital este dispositivo resolve. Exemplo: "Em ambientes restritos como salas de servidores, o controle de acesso tradicional por chave física é vulnerável a clonagem..."*


 ## ⚙️ 2. Funcionalidades do Dispositivo
- [x] Autenticação de dois fatores física (RFID + Senha em teclado matricial).
- [x] Detecção de abertura indevida de gabinete com sensor magnético/óptico.
- [x] Cifragem da carga de dados via algoritmo simétrico antes do envio via MQTT/HTTP.
- [x] Bloqueio temporal após 3 tentativas de acesso incorretas (*Anti-Brute Force*).


 ## 🛠️ 3. Especificações Técnicas e Componentes
- **Microcontrolador:** ESP32 NodeMCU-32S (Wi-Fi + BLE 4.2).
- **Sensores e Atuadores:** Módulo Leitor RFID RC522, Sensor de Presença PIR, Display OLED I2C 0.96", Buzzer Ativo.
- **Ambiente de Desenvolvimento:** Visual Studio Code com extensão PlatformIO.
- **Framework:** Arduino / ESP-IDF em Linguagem C/C++.


 ## 🔌 4. Diagrama de Conexões (Pinout)
*Insira aqui a imagem do circuito ou diagrama de blocos (Fritzing/Wokwi).*

 | Componente | Pino do Componente | Pino no ESP32 (GPIO) | Observações |
 | :--- | :--- | :--- | :--- |

| Módulo RFID | SDA (SS) | GPIO 5 | Linha SPI |
| Módulo RFID | SCK | GPIO 18 | Clock SPI |

| Display OLED | SDA | GPIO 21 | Linha I2C Padrão | 
| Display OLED | SCL | GPIO 22 | Linha I2C Padrão |
