using Microsoft.AspNetCore.Mvc;
using OfficeOpenXml;
using System.Data;
using System.Reflection;

namespace SportifyX.Domain.Helpers
{
    public static class ExcelGeneratorHelper
    {
        /// <summary>
        /// Generates an Excel file from any generic collection
        /// </summary>
        /// <typeparam name="T">The type of objects in the collection</typeparam>
        /// <param name="data">Collection of data to export to Excel</param>
        /// <param name="sheetName">Name of the Excel worksheet</param>
        /// <param name="fileName">Name of the Excel file to be generated (without extension)</param>
        /// <returns>FileContentResult containing the Excel file</returns>
        public static FileContentResult GenerateExcelFile<T>(IEnumerable<T> data, string sheetName = "Sheet1", string fileName = "ExportedData")
        {
            // Set the license context
            ExcelPackage.LicenseContext = LicenseContext.NonCommercial; // Change to Commercial if you have a license

            using var package = new ExcelPackage();
            var worksheet = package.Workbook.Worksheets.Add(sheetName);

            // Get properties of type T to use as column headers
            PropertyInfo[] properties = typeof(T).GetProperties();

            // Add headers
            for (int i = 0; i < properties.Length; i++)
            {
                worksheet.Cells[1, i + 1].Value = properties[i].Name;
                worksheet.Cells[1, i + 1].Style.Font.Bold = true;
            }

            // Add data
            int row = 2;
            foreach (var item in data)
            {
                for (int i = 0; i < properties.Length; i++)
                {
                    var value = properties[i].GetValue(item);
                    worksheet.Cells[row, i + 1].Value = value;
                }
                row++;
            }

            // Auto-fit columns
            worksheet.Cells.AutoFitColumns();

            // Convert to byte array
            var fileBytes = package.GetAsByteArray();

            // Return as FileContentResult
            return new FileContentResult(fileBytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            {
                FileDownloadName = $"{fileName}_{DateTime.UtcNow:yyyyMMdd}.xlsx"
            };
        }

        /// <summary>
        /// Generates an Excel file from any generic collection to the specified file path
        /// </summary>
        /// <typeparam name="T">The type of objects in the collection</typeparam>
        /// <param name="data">Collection of data to export to Excel</param>
        /// <param name="filePath">Full path where the file should be saved (including directory)</param>
        /// <param name="sheetName">Name of the Excel worksheet</param>
        /// <param name="fileName">Name of the Excel file to be generated (without extension)</param>
        /// <returns>Full path to the saved file</returns>
        public static string GenerateExcelFileToPath<T>(IEnumerable<T> data, string filePath, string sheetName = "Sheet1", string fileName = "ExportedData")
        {
            // Set the license context
            ExcelPackage.LicenseContext = LicenseContext.Commercial; // Change to Commercial if you have a license

            if (string.IsNullOrEmpty(filePath))
            {
                return string.Empty;
            }

            // Ensure directory exists
            string directory = Path.GetDirectoryName(filePath);

            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // If filePath is just a directory, create a full path with filename
            if (Directory.Exists(filePath))
            {
                filePath = Path.Combine(filePath, $"{fileName}_{DateTime.UtcNow:yyyyMMdd}.xlsx");
            }
            // If filePath doesn't have an extension, add .xlsx
            else if (!Path.HasExtension(filePath))
            {
                filePath = filePath + ".xlsx";
            }

            using var package = new ExcelPackage();
            var worksheet = package.Workbook.Worksheets.Add(sheetName);

            // Get properties of type T to use as column headers
            PropertyInfo[] properties = typeof(T).GetProperties();

            // Add headers
            for (int i = 0; i < properties.Length; i++)
            {
                worksheet.Cells[1, i + 1].Value = properties[i].Name;
                worksheet.Cells[1, i + 1].Style.Font.Bold = true;
            }

            // Add data
            int row = 2;
            foreach (var item in data)
            {
                for (int i = 0; i < properties.Length; i++)
                {
                    var value = properties[i].GetValue(item);
                    worksheet.Cells[row, i + 1].Value = value;
                }
                row++;
            }

            // Auto-fit columns
            worksheet.Cells.AutoFitColumns();

            // Save file to disk
            package.SaveAs(new FileInfo(filePath));

            return filePath;
        }

        /// <summary>
        /// Generates an Excel file from a DataTable
        /// </summary>
        /// <param name="dataTable">DataTable containing the data to export</param>
        /// <param name="sheetName">Name of the Excel worksheet</param>
        /// <param name="fileName">Name of the Excel file to be generated (without extension)</param>
        /// <returns>FileContentResult containing the Excel file</returns>
        public static FileContentResult GenerateExcelFileFromDataTable(DataTable dataTable, string sheetName = "Sheet1", string fileName = "ExportedData")
        {
            ExcelPackage.LicenseContext = LicenseContext.NonCommercial; // Change to Commercial if you have a license

            using var package = new ExcelPackage();
            var worksheet = package.Workbook.Worksheets.Add(sheetName);

            // Add headers
            for (int i = 0; i < dataTable.Columns.Count; i++)
            {
                worksheet.Cells[1, i + 1].Value = dataTable.Columns[i].ColumnName;
                worksheet.Cells[1, i + 1].Style.Font.Bold = true;
            }

            // Add data
            for (int row = 0; row < dataTable.Rows.Count; row++)
            {
                for (int col = 0; col < dataTable.Columns.Count; col++)
                {
                    worksheet.Cells[row + 2, col + 1].Value = dataTable.Rows[row][col];
                }
            }

            // Auto-fit columns
            worksheet.Cells.AutoFitColumns();

            // Convert to byte array
            var fileBytes = package.GetAsByteArray();

            // Return as FileContentResult
            return new FileContentResult(fileBytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            {
                FileDownloadName = $"{fileName}_{DateTime.UtcNow:yyyyMMdd}.xlsx"
            };
        }

        /// <summary>
        /// Generates an Excel file from a DataTable to the specified file path
        /// </summary>
        /// <param name="dataTable">DataTable containing the data to export</param>
        /// <param name="filePath">Full path where the file should be saved (including directory)</param>
        /// <param name="sheetName">Name of the Excel worksheet</param>
        /// <param name="fileName">Name of the Excel file to be generated (without extension)</param>
        /// <returns>Full path to the saved file</returns>
        public static string GenerateExcelFileFromDataTableToPath(DataTable dataTable, string filePath, string sheetName = "Sheet1", string fileName = "ExportedData")
        {
            ExcelPackage.LicenseContext = LicenseContext.Commercial; // Change to Commercial if you have a license

            if (string.IsNullOrEmpty(filePath))
            {
                return string.Empty;
            }

            // Ensure directory exists
            string directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // If filePath is just a directory, create a full path with filename
            if (Directory.Exists(filePath))
            {
                filePath = Path.Combine(filePath, $"{fileName}_{DateTime.UtcNow:yyyyMMdd}.xlsx");
            }
            // If filePath doesn't have an extension, add .xlsx
            else if (!Path.HasExtension(filePath))
            {
                filePath = filePath + ".xlsx";
            }

            using var package = new ExcelPackage();
            var worksheet = package.Workbook.Worksheets.Add(sheetName);

            // Add headers
            for (int i = 0; i < dataTable.Columns.Count; i++)
            {
                worksheet.Cells[1, i + 1].Value = dataTable.Columns[i].ColumnName;
                worksheet.Cells[1, i + 1].Style.Font.Bold = true;
            }

            // Add data
            for (int row = 0; row < dataTable.Rows.Count; row++)
            {
                for (int col = 0; col < dataTable.Columns.Count; col++)
                {
                    worksheet.Cells[row + 2, col + 1].Value = dataTable.Rows[row][col];
                }
            }

            // Auto-fit columns
            worksheet.Cells.AutoFitColumns();

            // Save file to disk
            package.SaveAs(new FileInfo(filePath));

            return filePath;
        }

        /// <summary>
        /// Extension method for IEnumerable to directly generate Excel
        /// </summary>
        public static FileContentResult ToExcel<T>(this IEnumerable<T> data, string sheetName = "Sheet1", string fileName = "ExportedData")
        {
            return GenerateExcelFile(data, sheetName, fileName);
        }

        /// <summary>
        /// Extension method for DataTable to directly generate Excel
        /// </summary>
        public static FileContentResult ToExcel<T>(this DataTable data, string sheetName = "Sheet1", string fileName = "ExportedData")
        {
            return GenerateExcelFileFromDataTable(data, sheetName, fileName);
        }

        /// <summary>
        /// Extension method for IEnumerable to directly generate Excel to the specified file path
        /// </summary>
        public static string ToExcel<T>(this IEnumerable<T> data, string filePath, string sheetName = "Sheet1", string fileName = "ExportedData")
        {
            return GenerateExcelFileToPath(data, filePath, sheetName, fileName);
        }

        /// <summary>
        /// Extension method for DatTable to directly generate Excel to the specified file path
        /// </summary>
        public static string ToExcel<T>(this DataTable data, string filePath, string sheetName = "Sheet1", string fileName = "ExportedData")
        {
            return GenerateExcelFileFromDataTableToPath(data, filePath, sheetName, fileName);
        }
    }
}
