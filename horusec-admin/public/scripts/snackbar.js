function showSnackBar(type) {
    document.getElementById(type).classList.add(`${type}-active`)

    setTimeout(() => {
        document.getElementById(type).classList.remove(`${type}-active`)
    }, 7000);
}
