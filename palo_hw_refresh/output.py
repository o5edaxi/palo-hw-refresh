"""Format the data nicely and write to disk"""
import logging
import xlsxwriter
from xlsxwriter.utility import xl_rowcol_to_cell
from xlsxwriter.utility import xl_col_to_name


def write_excel(myfw, comments, datasheet, filename):
    """
    Some more complex comparison logic is implemented directly with Excel functions to avoid having to normalize
    everything to numbers before the datasheet is written to Excel. This should give implementers of extract.py
    functions more peace of mind in that they only have to normalize the firewall's outputs and not the datasheet when
    new metrics or models are published, sometimes even with discrepancies in how the data is presented between
    different models in the datasheet. Normalizing Yes/No values to a number can also create ambiguities, for example:
    - Datasheet value is "Yes" for some models, and a digit capacity for others
    in this case normalizing "Yes" to "1" would simplify the Excel logic, but would make it impossible to understand
    if a firewall is at/over capacity or simply supports a certain feature.
    Generally the script aims to normalize (with some additional cleaning) numbers, throughputs, etc. as explained
    in extract.py, both in the firewall and the datasheets, and then the Excel formulas account for:
    - Yes/No
    - NA
    - TBD
    while everything else is marked in yellow for manual review.
    """
    workbook = xlsxwriter.Workbook(filename)
    worksheet = workbook.add_worksheet()
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#34CCEB',
        'border': 1
    })
    header_format_yellow = workbook.add_format({
        'bold': True,
        'bg_color': '#EAFF00',
        'border': 1
    })
    red_format = workbook.add_format({'bg_color': '#FF9999'})
    blue_format = workbook.add_format({'bg_color': '#99CCFF'})
    green_format = workbook.add_format({'bg_color': '#99FF99'})
    yellow_format = workbook.add_format({'bg_color': '#EAFF00'})
    percentage_format = workbook.add_format({'num_format': '0.0%'})
    # Write model names as headers
    models = list(datasheet.keys())
    worksheet.write(0, 1, 'IN_USE', header_format)
    worksheet.write(0, 2, 'COMMENTS', header_format)
    worksheet.write(0, 3, '% OF CURRENT MODEL', header_format)
    worksheet.write_formula(0, 4, '=A1', header_format)
    i_col = 5
    for model in models:
        worksheet.write(0, i_col, '% OF ' + model, header_format)
        worksheet.write(0, i_col + 1, model, header_format)
        i_col += 2
    # Write metrics as row headers and values
    metrics = list(next(iter(datasheet.values())).keys())
    for row, metric in enumerate(metrics, start=2):
        cell_measured = xl_rowcol_to_cell(row, 1)
        cell_selected = xl_rowcol_to_cell(row, 4)
        worksheet.write(row, 0, metric, header_format)
        # Percentage of selected model; additionally:
        # If measured value is Yes and DS value is No, set 101%
        # If measured value is Yes and DS value is Yes, set 0%
        # If measured value is No and DS value is No, set 0%
        # If measured value is No and DS value is Yes, set 0%
        worksheet.write_formula(row, 3, f'=IF(AND({cell_measured}="No", {cell_selected}="No"), 0, '
                                        f'IF(AND({cell_measured}="No", {cell_selected}="NA"), 0, '
                                        f'IF(AND({cell_measured}="Yes", {cell_selected}="NA"), 2, '
                                        f'IF(AND({cell_measured}="Yes", {cell_selected}="Yes"), 0, '
                                        f'IF(AND({cell_measured}="Yes", {cell_selected}="No"), 2, '
                                        f'IF(AND({cell_measured}="No", {cell_selected}="Yes"), 0, '
                                        f'{cell_measured}/{cell_selected}))))))', percentage_format)
        try:
            measured = myfw[metric]
            if measured == '__from_model__':
                logging.info('Found "__from_model__", copying datasheet for %s', metric)
                worksheet.write_formula(row, 1, f'={cell_selected}')
            else:
                worksheet.write(row, 1, measured)
            worksheet.write(row, 2, comments[metric])
        except KeyError:
            logging.warning('Did not find value %s for local firewall', metric)
            worksheet.write(row, 1, '__not_found__')
        # Model selected for comparison
        worksheet.write_formula(row, 4, f'=HLOOKUP($E$1,$F$1:${xl_rowcol_to_cell(row, len(models)*2+5)},{row+1},FALSE)')
        i_col = 5
        for model in models:
            cell_datasheet = xl_rowcol_to_cell(row, i_col+1)
            # Add a percentage column between each column, with extra Yes/No logic
            worksheet.write_formula(row, i_col, f'=IF(AND({cell_measured}="No", {cell_datasheet}="No"), 0, '
                                                f'IF(AND({cell_measured}="No", {cell_datasheet}="NA"), 0, '
                                                f'IF(AND({cell_measured}="Yes", {cell_datasheet}="NA"), 2, '
                                                f'IF(AND({cell_measured}="Yes", {cell_datasheet}="Yes"), 0, '
                                                f'IF(AND({cell_measured}="Yes", {cell_datasheet}="No"), 2, '
                                                f'IF(AND({cell_measured}="No", {cell_datasheet}="Yes"), 0, '
                                                f'{cell_measured}/{cell_datasheet}))))))', percentage_format)
            try:
                worksheet.write(row, i_col+1, datasheet[model][metric])
            except KeyError:
                logging.warning('Did not find value %s for model %s', metric, model)
            finally:
                i_col += 2
    # Dropdown menu to select your model for comparison
    worksheet.data_validation('A1', {
        'validate': 'list',
        'source': f'G1:${xl_rowcol_to_cell(1, len(models) * 2 + 5)}',
    })
    worksheet.write('A1', 'CLICK HERE TO SELECT COMPARISON MODEL', header_format_yellow)
    worksheet.write('A2', 'Datasheet values are colored based on the selected model', header_format_yellow)
    # Auto-adjust columns
    worksheet.set_column(0, 0, max(len(str(m)) for m in metrics) + 2)
    for col, model in enumerate(models, start=2):
        worksheet.set_column(col, col, max(len(model), 12))
    # Apply conditional formatting for percentages
    i_col = 3
    for _ in models:
        percentage_column = f'{xl_rowcol_to_cell(2, i_col)}:{xl_rowcol_to_cell(1000, i_col)}'
        worksheet.conditional_format(percentage_column, {
            'type': '2_color_scale',
            'min_color': '#FFFFFF',
            'max_color': '#FF0000',
            'min_value': 0,
            'max_value': 1,
            'max_type': 'num',
            'min_type': 'num'
        })
        if i_col > 4:
            # Apply conditional formatting for datasheets
            datasheet_column_letter = xl_col_to_name(i_col+1)
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=OR(ISBLANK(${datasheet_column_letter}3), ISBLANK($E3))',
                'format': yellow_format
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=${datasheet_column_letter}3=$E3',
                'format': blue_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(ISNUMBER(${datasheet_column_letter}3), ISNUMBER($E3)), ${datasheet_column_letter}3<$E3, FALSE)',
                'format': red_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(ISNUMBER(${datasheet_column_letter}3), ISNUMBER($E3)), ${datasheet_column_letter}3>$E3, FALSE)',
                'format': green_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(${datasheet_column_letter}3="No", $E3<>"No"), TRUE, FALSE)',
                'format': red_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(${datasheet_column_letter}3="NA", $E3<>"NA"), TRUE, FALSE)',
                'format': red_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(${datasheet_column_letter}3="TBD", $E3<>"TBD"), TRUE, FALSE)',
                'format': red_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(${datasheet_column_letter}3="Yes", $E3<>"Yes", NOT(ISNUMBER($E3))), TRUE, FALSE)',
                'format': green_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(${datasheet_column_letter}3<>"No", $E3="No"), TRUE, FALSE)',
                'format': green_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(${datasheet_column_letter}3<>"NA", $E3="NA"), TRUE, FALSE)',
                'format': green_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(${datasheet_column_letter}3<>"TBD", $E3="TBD"), TRUE, FALSE)',
                'format': green_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=IF(AND(${datasheet_column_letter}3<>"Yes", $E3="Yes", NOT(ISNUMBER(${datasheet_column_letter}3))), TRUE, FALSE)',
                'format': red_format,
                'stop_if_true': True
            })
            worksheet.conditional_format(f'{datasheet_column_letter}3:{datasheet_column_letter}1000', {
                'type': 'formula',
                'criteria': f'=${datasheet_column_letter}3<>$E3',
                'format': yellow_format
            })
        i_col += 2
    # Add comments
    worksheet.freeze_panes(1, 5)
    workbook.close()
