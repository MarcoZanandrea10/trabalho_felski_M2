import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class PipelineSimples {
    public static void main(String[] args) throws IOException {
        // String arquivoEntrada = "instrucoes.txt";
        String arquivoEntrada = "fib_rec_hexadecimal.txt";

        // Lê todas as instruções do arquivo
        List<String> instrucoes = Files.readAllLines(Paths.get(arquivoEntrada));

        System.out.println("SIMULADOR DE PIPELINE");
        System.out.println("Instruções originais: " + instrucoes.size() + "\n");

        // Simula os dois modos
        simularPipeline(instrucoes, false); // sem forwarding
        simularPipeline(instrucoes, true); // com forwarding
    }

    public static void simularPipeline(List<String> instrucoes, boolean forwarding) throws IOException {
        List<String> saida = new ArrayList<>(); // linhas de saída com endereços
        Map<Integer, String> mapa = new LinkedHashMap<>(); // mantém a ordem das instruções com endereços

        // Contadores de conflitos e NOPs
        int conflitosDados = 0;
        int conflitosControle = 0;
        int nopsInseridos = 0;
        int endereco = 0; // endereço inicial
        String regDestinoAnterior = ""; // registrador destino da instrução anterior

        // Percorre todas as instruções
        for (String instrucao : instrucoes) {
            instrucao = instrucao.trim();
            if (instrucao.isEmpty())
                continue;

            mapa.put(endereco, instrucao);
            endereco += 4;

            // arrumar a deteccao de conflitos de controle e arrumar o NOPs (add sempre 3)
            // ARRUMAR OS NOPS

            // Detecta conflito de controle
            if (instrucao.startsWith("BEQ") || instrucao.startsWith("BNE") || instrucao.startsWith("J")) {
                conflitosControle++;

                for (int i = 0; i < 3; i++) {
                    mapa.put(endereco, "NOP");
                    endereco += 4;
                    nopsInseridos++;
                }

                regDestinoAnterior = "";
                continue;
            }

            // Detecta conflito de dados
            String semVirgulas = instrucao.replace(",", "");
            String[] partes = semVirgulas.split("\\s+");

            if (partes.length >= 3) {
                String rd = partes[1]; // destino desta instrução
                String rs = partes[2]; // fonte 1
                String rt = partes.length >= 4 ? partes[3] : "";

                if (!regDestinoAnterior.isEmpty() && (rs.equals(regDestinoAnterior) || rt.equals(regDestinoAnterior))) {
                    conflitosDados++;

                    for (int i = 0; i < 3; i++) {
                        mapa.put(endereco, "NOP");
                        endereco += 4;
                        nopsInseridos++;
                    }
                }

                regDestinoAnterior = rd;
            }

        }

        // Monta resultado com endereços
        for (Map.Entry<Integer, String> e : mapa.entrySet()) {
            String endHex = String.format("0x%04X", e.getKey());
            saida.add(endHex + "  " + e.getValue());
        }

        System.out.println("Resultado (" + (forwarding ? "Com" : "Sem") + " Forwarding)");
        System.out.println("Conflitos de Dados: " + conflitosDados);
        System.out.println("Conflitos de Controle: " + conflitosControle);
        System.out.println("NOPs Inseridos: " + nopsInseridos);
        System.out.println("Sobrecusto: +" + nopsInseridos + " instruções");
        System.out.println("Total final: " + (instrucoes.size() + nopsInseridos));
        System.out.println("Endereço final: 0x" + String.format("%04X", (mapa.size() * 4) - 4));
        System.out.println("\n--------------------------------------------\n");

        String nomeSaida = forwarding ? "saida_com_forwarding.txt" : "saida_sem_forwarding.txt";
        Files.write(Paths.get(nomeSaida), saida);
    }
}