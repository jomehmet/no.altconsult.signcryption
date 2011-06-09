package no.altconsult.signcryption;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Benchmark {
	private static HashMap<String, Long> benchmarks = 
		new HashMap<String,Long>();
	private static HashMap<String, Long> benchmarks_avg = 
		new HashMap<String,Long>();
	public static void START(String id){
		benchmarks.put(id, 
				Long.valueOf(System.currentTimeMillis()));
	}
	public static void STOP_Print(String id){
		if(benchmarks.containsKey(id))
			System.out.println("Benchmark - " 
					+ id + ": " 
					+ (System.currentTimeMillis() 
					- (long)benchmarks.get(id))+"ms");
		else
			System.out.println("Benchmark - unknown id");
	}
	public static String STOP_old(String id){
		return "Benchmark -> " + id + ": " 
		+ (System.currentTimeMillis() 
		- (long)benchmarks.get(id) + " ms");
	}
	public static String STOP(String id){
		long thisRound = System.currentTimeMillis()-
		(long)benchmarks.get(id);
		benchmarks_avg.put(id,
				thisRound + 
				(benchmarks_avg.containsKey(id)?benchmarks_avg.get(id):0));
		return id + ":" + thisRound;
	}
	public static String getResult(String id, int rounds){
		return id + ": " +
		(long)benchmarks_avg.get(id)/rounds + " ms";
	}
	public static String getAllResults(int rounds){
		String res = "";
	    Iterator it = benchmarks_avg.entrySet().iterator();
	    while (it.hasNext()) {
	        Map.Entry pairs = (Map.Entry)it.next();
	        res += getResult((String)pairs.getKey(), rounds)+"\n";
	    }
	    return res;
	}
	
	
	public static void resetAll(){
		benchmarks.clear();
		benchmarks_avg.clear();
	}
}
