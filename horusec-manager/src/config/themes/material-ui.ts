import { createMuiTheme } from '@material-ui/core';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';

const theme = getCurrentTheme();

const themeMatUi = createMuiTheme({
  palette: {
    primary: {
      // primary color
      main: theme.colors.primary, // black
    },
    secondary: {
      main: theme.colors.secondary,
    },
  },

  overrides: {
    MuiInputBase: {
      root: {
        color: theme.colors.input.text,
      },
      input: {
        '&::-webkit-calendar-picker-indicator': {
          filter: 'invert(1)',
        },
        '&:-webkit-autofill': {
          '-webkit-text-fill-color': 'white',
          '-webkit-box-shadow': '0 0 0 30px rgb(28 28 30) inset !important',
        },
      },
    },
    MuiInput: {
      underline: {
        '&:$before': {
          borderColor: theme.colors.input.border,
        },
        '&:$after': {
          borderColor: theme.colors.input.border,
        },
        '&:$hover:$not(.Mui-disable):$before': {
          borderColor: theme.colors.input.border,
        },
      },
    },
    MuiFormLabel: {
      root: {
        color: theme.colors.input.label,
        '&$focused': {
          color: theme.colors.input.label,
        },
      },
      focused: {},
    },
    MuiInputLabel: {
      root: {
        color: theme.colors.input.label,
      },
    },
    MuiIconButton: {
      root: {
        color: theme.colors.button.text,
      },
    },

    MuiCheckbox: {
      root: {
        color: theme.colors.checkbox.border,
      },
      colorSecondary: {
        '&$checked': {
          color: theme.colors.checkbox.checked.secundary,
        },
      },
      checked: {},
    },
    MuiPaper: {
      root: {
        color: 'white',
        backgroundColor: theme.colors.background.highlight,

        '& .MuiPickersBasePicker-container': {
          backgroundColor: theme.colors.background.highlight,
        },
        '& .MuiPickersDay-day': {
          color: 'white',
        },
        '& .MuiPickersCalendarHeader-dayLabel': {
          color: 'white',
        },
        '& .MuiPickersCalendarHeader-iconButton': {
          background: 'none',
          color: '#fff',
        },
      },
    },
    // MuiIconButton: {
    //   root: {
    //     color: theme.colors.icon.primary
    //   }
    // }
  },
});

export default themeMatUi;
