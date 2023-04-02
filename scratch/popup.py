from flask import Flask, render_template
import pymongo
import pandas as pd
import ipywidgets as widgets

app = Flask(__name__)

# create a connection to your MongoDB database
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["users"]
collection = db["detections"]

# create a pandas dataframe with the table data
data = {'Tactic': ['Initial Access', 'Execution', 'Persistence'],
        'Technique': ['Spearphishing Attachment', 'Command and Scripting Interpreter', 'Create Account'],
        'Description': ['Phishing email with a malicious attachment is sent to the target', 'Adversary runs commands or scripts on the target system', 'Adversary creates a new user account with elevated privileges']}
df = pd.DataFrame(data)

# create a hover function to show a pop-up box with the description from MongoDB
def show_description(row, col):
    technique = df.loc[row, 'Technique']
    description = collection.find_one({'technique': technique})['description']
    tooltip = widgets.HTML(value="<p style='width: 300px; font-weight:bold; color: #333;'>{0}</p>".format(description))
    widgets.dlink((tooltip, 'value'), (out, 'value'))
    return tooltip

# define a Flask route to render the interactive table
@app.route('/')
def index():
    # create the table
    table = widgets.HTML(
        value=df.to_html(classes='table table-striped table-hover'),
        placeholder='No data available',
    )

    # create an output widget to display the pop-up box
    out = widgets.Output()

    # add the hover functionality to the table
    def on_hover(change):
        if change['type'] == 'hover':
            row, col = change['owner'].selected_cell
            if row is not None and col is not None:
                tooltip = show_description(row, col)
                with out:
                    out.clear_output()
                    display(tooltip)

    table.observe(on_hover, 'selected_cell')

    # render the template with the table and output widget
    return render_template('index.html', table=table, out=out)

if __name__ == '__main__':
    app.run(debug=True)
