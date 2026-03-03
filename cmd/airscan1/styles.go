// Copyright 2020 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	colorGreen  = lipgloss.AdaptiveColor{Light: "2", Dark: "10"}
	colorYellow = lipgloss.AdaptiveColor{Light: "3", Dark: "11"}
	colorRed    = lipgloss.AdaptiveColor{Light: "1", Dark: "9"}
	colorDim    = lipgloss.AdaptiveColor{Light: "8", Dark: "8"}
	colorHeader = lipgloss.AdaptiveColor{Light: "4", Dark: "12"}

	styleSuccess = lipgloss.NewStyle().Foreground(colorGreen)
	styleWarning = lipgloss.NewStyle().Foreground(colorYellow)
	styleError   = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	styleInfo    = lipgloss.NewStyle().Foreground(colorDim)
	styleHeader  = lipgloss.NewStyle().Foreground(colorHeader).Bold(true)
	styleBorder  = lipgloss.NewStyle().Foreground(colorDim)
)

func printInfo(format string, args ...any) {
	fmt.Println(styleInfo.Render(fmt.Sprintf(format, args...)))
}

func printSuccess(format string, args ...any) {
	fmt.Println(styleSuccess.Render("✓ " + fmt.Sprintf(format, args...)))
}

func printWarning(format string, args ...any) {
	fmt.Println(styleWarning.Render("⚠ " + fmt.Sprintf(format, args...)))
}

func printError(err error) {
	fmt.Fprintln(os.Stderr, styleError.Render("error: "+err.Error()))
}

func printDebug(format string, args ...any) {
	if debugMode {
		fmt.Println(styleInfo.Render("[debug] " + fmt.Sprintf(format, args...)))
	}
}

func newDeviceTable(rows [][]string) *table.Table {
	return table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(styleBorder).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return styleHeader
			}
			return lipgloss.NewStyle()
		}).
		Headers("NAME", "HOST", "IPs").
		Rows(rows...)
}
