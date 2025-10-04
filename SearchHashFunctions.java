import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.mem.Memory;

class Algorithm32
{
	public List<Integer> consts;
	public boolean isfirst = false;
	public int viter = 0;
	public Address metka;
	public int sizec = 0;
	public String name;
	public int[] constants; 
	public int maxsizeblock;
	public int min;
	public Algorithm32(int[] con, String n, Address a, int blocksize, int m)
	{
		min = m;
		maxsizeblock = blocksize;
		constants = con;
		name = n;
		consts = new ArrayList<>(Arrays.stream(constants).boxed().toList());
		sizec = consts.size();
		metka = a;
	}
	public void newcon()
	{
		consts = new ArrayList<>(Arrays.stream(constants).boxed().toList());
	}
	public void nextviter()
	{
		if(isfirst)viter++;
	}
	public String genLabName()
	{
		float p = 100.0f / (float)(sizec); 
		return name + String.format(" %d", (int)( ( (float) (sizec - consts.size())) * p) ) + "%";
	}
}

public class SearchHashFunctions extends GhidraScript 
{
	public int[] constantssha256 = {0x06ca6351,0x0fc19dc6,0x106aa070,
			0x12835b01,0x14292967,0x19a4c116,0x1e376c08,0x240ca1cc,
			0x243185be,0x2748774c,0x27b70a85,0x2de92c6f,0x2e1b2138,
			0x34b0bcb5,0x391c0cb3,0x3956c25b,0x428a2f98,0x4a7484aa,
			0x4d2c6dfc,0x4ed8aa4a,0x53380d13,0x550c7dc3,0x59f111f1,
			0x5b9cca4f,0x5cb0a9dc,0x650a7354,0x682e6ff3,0x71374491,
			0x72be5d74,0x748f82ee,0x766a0abb,0x76f988da,0x78a5636f,
			0x80deb1fe,0x81c2c92e,0x84c87814,0x8cc70208,0x90befffa,
			0x923f82a4,0x92722c85,0x983e5152,0x9bdc06a7,0xa2bfe8a1,
			0xa4506ceb,0xa81a664b,0xa831c66d,0xab1c5ed5,0xb00327c8,
			0xb5c0fbcf,0xbef9a3f7,0xbf597fc7,0xc19bf174,0xc24b8b70,
			0xc6e00bf3,0xc76c51a3,0xd192e819,0xd5a79147,0xd6990624,
			0xd807aa98,0xe49b69c1,0xe9b5dba5,0xefbe4786,0xf40e3585}; 
	
	public int[] constantssha1 = {0x67452301,0xEFCDAB89,0x98BADCFE,
			0x10325476,0xC3D2E1F0,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,
			0xCA62C1D6}; 
	
	public int[] constantsMD5 = {0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
		    0xd76aa478,0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 
		    0x4787c62a,0xa8304613, 0xfd469501,0x698098d8, 0x8b44f7af, 
		    0xffff5bb1, 0x895cd7be,0x6b901122,0xfd987193, 0xa679438e, 
		    0x49b40821,0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,0x21e1cde6, 
		    0xc33707d6, 0xf4d50d87, 0x455a14ed,0xa9e3e905, 0xfcefa3f8, 
		    0x676f02d9, 0x8d2a4c8a,0xfffa3942, 0x8771f681, 0x6d9d6122, 
		    0xfde5380c,0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,0xd9d4d039, 
		    0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,0xf4292244, 0x432aff97, 
		    0xab9423a7, 0xfc93a039,0x655b59c3, 0x8f0ccc92, 0xffeff47d, 
		    0x85845dd1,0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1};

	@Override
	 protected void run() throws Exception 
	 {
	    JCheckBox sha1 = new JCheckBox("SHA1");
	    JCheckBox sha256 = new JCheckBox("SHA256", true);
	    JCheckBox md5 = new JCheckBox("MD5");
	    JPanel panel = new JPanel(new GridLayout(0,1));
	    panel.add(sha1);
	    panel.add(sha256);
	    panel.add(md5);
	    int result = JOptionPane.showConfirmDialog(null, panel, 
	        "Выбор хешей", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

	    if (result != JOptionPane.OK_OPTION) 
	    {
	    	return;
	    }
	    if(!sha1.isSelected() && !sha256.isSelected() && !md5.isSelected()) return;
	    
		 if(sha256.isSelected())Arrays.sort(constantssha256);
		 if(sha1.isSelected())Arrays.sort(constantssha1);
		 if(md5.isSelected())Arrays.sort(constantsMD5);
		 if(md5.isSelected())Arrays.sort(constantsMD5);
	     Memory mem = currentProgram.getMemory();
	     Address start = mem.getMinAddress();
	     Address end = mem.getMaxAddress();

	     boolean next = false;
	     Address addr = start;
	     List<Algorithm32> al = new ArrayList<>();
	     if(sha256.isSelected())al.add(new Algorithm32(constantssha256,"SHA256",start,0x2000,16));
	     if(sha1.isSelected())al.add(new Algorithm32(constantssha1,"SHA-1",start,0x400,2));
	     if(md5.isSelected())al.add(new Algorithm32(constantsMD5,"MD5",start,0x2000,16));
	     byte[] data = new byte[4];
	     
	     while (addr.compareTo(end) < 0) 
	     {

	    	 
	    	 
	         if (mem.contains(addr)) 
	         {
	             
	             try 
	             {

	                 mem.getBytes(addr, data);
	                 int val = ((int)(data[3] & 0xFF) << 24) |
	                            ((int)(data[2] & 0xFF) << 16) |
	                            ((int)(data[1] & 0xFF) << 8)  |
	                            ((int)(data[0] & 0xFF));
	                 for (Algorithm32 algorithm32 : al)
	                 {
		                 if(Arrays.binarySearch(algorithm32.constants, val) >= 0)
		                 {
		                	 
		                	 long numericAddress = addr.getOffset();
		                	 if(!algorithm32.isfirst) 
		                	 {
		                		 algorithm32.isfirst = true;
		                		 algorithm32.metka = addr;
		                	 }
		                	 next = true;
		                	 
		                	 algorithm32.consts.remove((Integer)val);
		                	 algorithm32.viter += 4;
		                	 break;
		                 }
		                 if(algorithm32.viter > algorithm32.maxsizeblock)
	        	    	 {
	        	    		 algorithm32.isfirst = false;
	        	    		 
	        	    		 if(algorithm32.consts.size() <= algorithm32.min)
	        	    		 {
	        	    			 String lab = algorithm32.genLabName();
			                	 long numericAddress = algorithm32.metka.getOffset();
			                	 println(lab+" " + Long.toHexString(numericAddress));

			                     currentProgram.getListing().setComment(algorithm32.metka, CommentType.PRE, lab);
	        	    		 }
	        	    		 algorithm32.newcon();
	        	    		 algorithm32.viter = 0;
	        	    	 }
	                 }

	             } catch (Exception e) 
	             {
	                 
	             }
	         }
	         for (Algorithm32 a : al) 
	         {
	        	 a.nextviter();
			 }
	         
	         if(next)
	        	 {
	        	 addr = addr.add(4);
	        	 next = false;
	        	 }
	         else 
	         {
	        	 addr = addr.add(1); 
	         }
	     }
	 }
}