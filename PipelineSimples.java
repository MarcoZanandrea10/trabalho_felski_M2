import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class PipelineSimples {
    public static void main(String[] args) throws IOException {
        String arquivoEntrada = "instrucoes.txt";

        // Lê todas as instruções do arquivo
        List<String> instrucoes = Files.readAllLines(Paths.get(arquivoEntrada));

        System.out.println("SIMULADOR DE PIPELINE");
        System.out.println("Instruções originais: " + instrucoes.size() + "\n");

        // Simula os dois modos
        simularPipeline(instrucoes, false); // sem forwarding
        simularPipeline(instrucoes, true);  // com forwarding
    }

    public static void simularPipeline(List<String> instrucoes, boolean forwarding) throws IOException {
        List<String> saida = new ArrayList<>();
        Map<Integer, String> mapa = new LinkedHashMap<>();

        int conflitosDados = 0;
        int conflitosControle = 0;
        int nopsInseridos = 0;

        int endereco = 0; // endereço inicial
        String regAnterior = "";

        // Percorre todas as instruções
        for (String instrucao : instrucoes) {
            instrucao = instrucao.trim();
            if (instrucao.isEmpty()) continue;

            mapa.put(endereco, instrucao);
            endereco += 4;

            // Detecta conflito de controle
            if (instrucao.startsWith("BEQ") || instrucao.startsWith("BNE") || instrucao.startsWith("J")) {
                conflitosControle++;
                if (!forwarding) {
                    mapa.put(endereco, "NOP");
                    endereco += 4;
                    nopsInseridos++;
                }
                regAnterior = "";
                continue;
            }

            // Detecta conflito de dados
            String[] partes = instrucao.replace(",", "").split(" ");
            if (partes.length >= 2) {
                String destino = partes[1]; // registrador destino

                if (!regAnterior.isEmpty() && instrucao.contains(regAnterior)) {
                    conflitosDados++;
                    int qtNops = forwarding ? 1 : 2;
                    for (int i = 0; i < qtNops; i++) {
                        mapa.put(endereco, "NOP");
                        endereco += 4;
                        nopsInseridos++;
                    }
                }
                regAnterior = destino;
            }
        }

        // Monta resultado com endereços
        for (Map.Entry<Integer, String> e : mapa.entrySet()) {
            String endHex = String.format("0x%04X", e.getKey());
            saida.add(endHex + "  " + e.getValue());
        }

        // Mostra o relatório
        System.out.println("Resultado (" + (forwarding ? "Com" : "Sem") + " Forwarding)");
        System.out.println("Conflitos de Dados: " + conflitosDados);
        System.out.println("Conflitos de Controle: " + conflitosControle);
        System.out.println("NOPs Inseridos: " + nopsInseridos);
        System.out.println("Sobrecusto: +" + nopsInseridos + " instruçoes");
        System.out.println("Total final: " + (instrucoes.size() + nopsInseridos));
        System.out.println("Endereço final: 0x" + String.format("%04X", endereco - 4));
        System.out.println("\n--------------------------------------------\n");

        // Salva o resultado em arquivo
        String nomeSaida = forwarding ? "saida_com_forwarding.txt" : "saida_sem_forwarding.txt";
        Files.write(Paths.get(nomeSaida), saida);
    }
}