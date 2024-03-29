# Mapping Rules Techniques to Mitre Navigator

This script generates a MITRE ATT&CK Navigator layer based on the techniques covered by a set of rules defined in an Excel or CSV file.

## Usage

1. Install the required Python modules using the following command:
```
pip install openpyxl pandas PyGithub
```

2. Run the script and select the Excel file containing the rules when prompted.

3. The script will generate a `MITRE_Matrix.json` file that can be imported into the MITRE ATT&CK Navigator.

4. The script will push the generated `MITRE_Matrix.json` file to a Github repository using your Github access token. The repository name and access token can be configured in the script.

5. The script will generate two files in the same directory as the Excel file:
   - `MITRE_Matrix.json`: the JSON file that can be imported into MITRE Navigator
   - `Mitre Navigator.html`: a HTML file that can be used to visualize the matrix in the browser

## Example Excel File Format

The Excel file should contain a sheet named "Rules" with the following columns:

| Rule Name | MITRE Tactic | MITRE Technique |
| --- | --- | --- |
| Rule 1 | Tactic 1, Tactic 2 | Technique 1, Technique 2 |
| Rule 2 | Tactic 3 | Technique 3, Technique 4, Technique 5 |

The script will extract the unique techniques from the "MITRE Technique" column and generate a MITRE Navigator layer with the techniques as the only data points. 
The tactics defined in the "MITRE Tactic" column are used to group the techniques in the Navigator.

## Github Repository

The `MITRE_Matrix.json` file can be automatically pushed to a Github repository using the Github API. To enable this feature, set the `Github_Access_Token` variable in the script to a valid Github personal access token with the necessary permissions.

By default, the script will push the `MITRE_Matrix.json` file to a repository named "Automation-Scripts" in the authenticated user's Github account. To push the file to a different repository, modify the `Repo_name` variable in the script.

## Output Files
The script generates two files:

## MITRE_Matrix.json
This file contains the MITRE ATT&CK matrix layer in JSON format. The file can be imported into MITRE Navigator to visualize the coverage of techniques by a set of rules.

## Mitre Navigator.html
This file is a HTML file that can be used to visualize the matrix in the browser. The file contains the script to load the JSON file and generate the matrix using the MITRE Navigator interface.

## License

This script is licensed under the [MIT License](https://github.com/yourusername/Automation-Scripts/blob/main/LICENSE).
